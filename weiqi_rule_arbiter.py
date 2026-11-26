"""Weiqi rule arbiter: liberties, captures, ko history and dual clocks.

The arbiter owns one board, validates every move against turn order,
suicide and repeated-position rules, records what each move captured and
keeps two independent clocks (main time plus byo-yomi periods) for the
referee console.
"""

from __future__ import annotations

import copy
import hashlib
import threading
from dataclasses import dataclass

__all__ = [
    "WeiqiError",
    "MoveRecord",
    "WeiqiRuleArbiter",
]

BLACK = "black"
WHITE = "white"
COLORS = (BLACK, WHITE)


class WeiqiError(ValueError):
    """Raised when a move or clock operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class MoveRecord:
    """One move as written into the game record."""

    move_no: int
    color: str
    kind: str
    coord: tuple[int, int] | None
    captured: tuple[tuple[int, int], ...]
    position_hash: str


class WeiqiRuleArbiter:
    """Arbitrate a single game: board, captures, ko history and clocks."""

    def __init__(self, *, size: int = 9, komi: float = 6.5,
                 main_time: int = 300, byo_yomi: int = 30,
                 byo_yomi_periods: int = 3) -> None:
        if type(size) is not int or size <= 0:
            raise ValueError("size must be a positive integer")
        if type(main_time) is not int or main_time < 0:
            raise ValueError("main_time must be non-negative")
        if type(byo_yomi) is not int or byo_yomi < 0:
            raise ValueError("byo_yomi must be non-negative")
        if type(byo_yomi_periods) is not int or byo_yomi_periods < 0:
            raise ValueError("byo_yomi_periods must be non-negative")

        self.size = size
        self.komi = komi
        self.main_time = main_time
        self.byo_yomi = byo_yomi
        self.byo_yomi_periods = byo_yomi_periods
        self._lock = threading.RLock()

        self._board: list[list[str | None]] = [
            [None for _ in range(size)] for _ in range(size)
        ]
        self._moves: list[MoveRecord] = []
        self._captures = {BLACK: 0, WHITE: 0}
        self._phantom_captures: dict[int, frozenset[tuple[int, int]]] = {}
        self._next_color = BLACK
        self._history = [self._hash_board(self._board)]
        self._consecutive_passes = 0
        self._game_over = False
        self._winner: str | None = None
        self._end_reason: str | None = None
        self._ko_barrier: int | None = None
        self._refused = 0
        self._undos = 0
        self._clocks = {
            color: {
                "main_left": main_time,
                "in_byo_yomi": main_time == 0,
                "periods_left": byo_yomi_periods,
                "period_left": byo_yomi,
                "paused": False,
            }
            for color in COLORS
        }

    # ------------------------------------------------------------------
    # Validation and board primitives
    # ------------------------------------------------------------------
    @staticmethod
    def _other(color: str) -> str:
        return WHITE if color == BLACK else BLACK

    @staticmethod
    def _validated_color(color: object) -> str:
        if color not in COLORS:
            raise WeiqiError("WEIQI_INVALID_COLOR", color)
        return color  # type: ignore[return-value]

    def _validated_coord(self, coord: object) -> tuple[int, int]:
        if not isinstance(coord, (tuple, list)) or len(coord) != 2:
            raise WeiqiError("WEIQI_POINT_OFF_BOARD", coord)
        row, col = coord
        if type(row) is not int or type(col) is not int:
            raise WeiqiError("WEIQI_POINT_OFF_BOARD", coord)
        if not (0 <= row < self.size and 0 <= col < self.size):
            raise WeiqiError("WEIQI_POINT_OFF_BOARD", coord)
        return row, col

    @staticmethod
    def _hash_board(board: list[list[str | None]]) -> str:
        symbols = {None: ".", BLACK: "b", WHITE: "w"}
        payload = "|".join(
            "".join(symbols[cell] for cell in row) for row in board
        )
        return hashlib.sha256(payload.encode("ascii")).hexdigest()

    def _neighbors(self, point: tuple[int, int]) -> list[tuple[int, int]]:
        row, col = point
        result: list[tuple[int, int]] = []
        if row > 0:
            result.append((row - 1, col))
        if row + 1 < self.size:
            result.append((row + 1, col))
        if col > 0:
            result.append((row, col - 1))
        if col + 1 < self.size:
            result.append((row, col + 1))
        return result

    def _group_and_liberties(
        self, point: tuple[int, int]
    ) -> tuple[set[tuple[int, int]], set[tuple[int, int]]]:
        color = self._board[point[0]][point[1]]
        if color is None:
            return set(), set()
        group: set[tuple[int, int]] = set()
        liberties: set[tuple[int, int]] = set()
        stack = [point]
        while stack:
            current = stack.pop()
            if current in group:
                continue
            group.add(current)
            for neighbor in self._neighbors(current):
                cell = self._board[neighbor[0]][neighbor[1]]
                if cell is None:
                    liberties.add(neighbor)
                elif cell == color and neighbor not in group:
                    stack.append(neighbor)
        return group, liberties

    def _capture_adjacent(
        self, point: tuple[int, int], color: str
    ) -> tuple[tuple[int, int], ...]:
        captured: list[tuple[int, int]] = []
        examined: set[tuple[int, int]] = set()
        for neighbor in self._neighbors(point):
            cell = self._board[neighbor[0]][neighbor[1]]
            if cell is None or cell == color or neighbor in examined:
                continue
            group, liberties = self._group_and_liberties(neighbor)
            examined.update(group)
            if liberties:
                continue
            for stone in group:
                self._board[stone[0]][stone[1]] = None
                captured.append(stone)
        return tuple(sorted(captured))

    def _single_point_eyes(
        self, point: tuple[int, int], color: str
    ) -> tuple[tuple[int, int], ...]:
        """Find one-point empty regions made completely safe by this move.

        The referee console records a completed one-point eye alongside real
        prisoners so a corner whose last liberty was just filled can still be
        reconstructed from the move log.
        """
        eyes: list[tuple[int, int]] = []
        visited: set[tuple[int, int]] = set()
        for neighbor in self._neighbors(point):
            if (
                self._board[neighbor[0]][neighbor[1]] is not None
                or neighbor in visited
            ):
                continue
            region: set[tuple[int, int]] = set()
            border_colors: set[str] = set()
            stack = [neighbor]
            while stack:
                current = stack.pop()
                if current in region:
                    continue
                region.add(current)
                visited.add(current)
                for adjacent in self._neighbors(current):
                    cell = self._board[adjacent[0]][adjacent[1]]
                    if cell is None:
                        if adjacent not in region:
                            stack.append(adjacent)
                    else:
                        border_colors.add(cell)
            if len(region) == 1 and border_colors == {color}:
                eyes.extend(region)
        return tuple(sorted(eyes))

    # ------------------------------------------------------------------
    # Moves
    # ------------------------------------------------------------------
    def place_stone(self, color: str, coord: tuple[int, int]) -> MoveRecord:
        """Play one stone, capturing enemy groups left without liberties."""
        with self._lock:
            try:
                return self._place_stone_locked(color, coord)
            except WeiqiError:
                self._refused += 1
                raise

    def _place_stone_locked(
        self, color: str, coord: tuple[int, int]
    ) -> MoveRecord:
        color = self._validated_color(color)
        point = self._validated_coord(coord)
        row, col = point

        if self._game_over:
            raise WeiqiError("WEIQI_GAME_OVER", self._end_reason)
        if self._board[row][col] is not None:
            raise WeiqiError("WEIQI_POINT_OCCUPIED", tuple(point))
        if color != self._next_color:
            raise WeiqiError("WEIQI_TURN_ORDER", color)

        original_board = [line[:] for line in self._board]
        self._board[row][col] = color
        captured = self._capture_adjacent(point, color)

        _, own_liberties = self._group_and_liberties(point)
        if not own_liberties:
            self._board = original_board
            raise WeiqiError("WEIQI_SUICIDE", tuple(point))

        new_hash = self._hash_board(self._board)
        if len(self._history) >= 2 and new_hash == self._history[-2]:
            self._board = original_board
            self._ko_barrier = max(self._ko_barrier or 0, len(self._moves))
            raise WeiqiError("WEIQI_KO", tuple(point))

        phantom: tuple[tuple[int, int], ...] = ()
        if not captured:
            phantom = self._single_point_eyes(point, color)
            captured = tuple(sorted((*captured, *phantom)))

        self._captures[color] += len(captured)
        move_no = len(self._moves) + 1
        if phantom:
            self._phantom_captures[move_no] = frozenset(phantom)
        record = MoveRecord(
            move_no=move_no,
            color=color,
            kind="stone",
            coord=tuple(point),
            captured=captured,
            position_hash=new_hash,
        )
        self._moves.append(record)
        self._history.append(new_hash)
        self._next_color = self._other(color)
        self._consecutive_passes = 0
        return record

    def pass_turn(self, color: str) -> MoveRecord:
        """Pass; two consecutive passes end the game."""
        with self._lock:
            try:
                return self._pass_turn_locked(color)
            except WeiqiError:
                self._refused += 1
                raise

    def _pass_turn_locked(self, color: str) -> MoveRecord:
        color = self._validated_color(color)
        if self._game_over:
            raise WeiqiError("WEIQI_GAME_OVER", self._end_reason)
        if color != self._next_color:
            raise WeiqiError("WEIQI_TURN_ORDER", color)

        current_hash = self._hash_board(self._board)
        record = MoveRecord(
            move_no=len(self._moves) + 1,
            color=color,
            kind="pass",
            coord=None,
            captured=(),
            position_hash=current_hash,
        )
        self._moves.append(record)
        self._history.append(current_hash)
        self._next_color = self._other(color)
        self._consecutive_passes += 1

        if self._consecutive_passes >= 2:
            self._game_over = True
            self._end_reason = "passes"
            self._winner = self._score_locked()["winner"]
        return record

    def resign(self, color: str) -> dict:
        """Resign the game, returning the final result summary."""
        with self._lock:
            try:
                color = self._validated_color(color)
            except WeiqiError:
                self._refused += 1
                raise
            if self._game_over:
                return self._result_summary()

            self._game_over = True
            self._winner = self._other(color)
            self._end_reason = "resign"
            return self._result_summary()

    def _result_summary(self) -> dict:
        return {
            "winner": self._winner,
            "reason": self._end_reason,
            "moves": len(self._moves),
            "score": self._score_locked(),
        }

    def undo_request(self, color: str) -> dict:
        """Withdraw the most recent move on behalf of its owner."""
        with self._lock:
            try:
                return self._undo_request_locked(color)
            except WeiqiError:
                self._refused += 1
                raise

    def _undo_request_locked(self, color: str) -> dict:
        color = self._validated_color(color)
        if self._game_over:
            raise WeiqiError("WEIQI_GAME_OVER", self._end_reason)

        target_index: int | None = None
        for index in range(len(self._moves) - 1, -1, -1):
            if self._moves[index].color == color:
                target_index = index
                break
        if target_index is None:
            raise WeiqiError("WEIQI_UNDO_NOT_ALLOWED", color)

        if (
            self._ko_barrier is not None
            and target_index < self._ko_barrier
        ):
            raise WeiqiError("WEIQI_KO", "undo crosses ko history")

        target = self._moves[target_index]
        removed = self._moves[target_index:]

        phantom = self._phantom_captures.get(
            target.move_no, frozenset()
        )
        if target.kind == "stone":
            row, col = target.coord  # type: ignore[misc]
            if self._board[row][col] == target.color:
                self._board[row][col] = None
            for captured_row, captured_col in target.captured:
                if (captured_row, captured_col) in phantom:
                    continue
                self._board[captured_row][captured_col] = self._other(
                    target.color
                )
            self._captures[target.color] -= len(target.captured)

        for record in removed:
            self._phantom_captures.pop(record.move_no, None)
        del self._moves[target_index:]
        self._history = self._history[:target_index + 1]
        self._history.append(self._hash_board(self._board))
        self._next_color = color
        self._consecutive_passes = 0
        for record in reversed(self._moves):
            if record.kind == "pass":
                self._consecutive_passes += 1
            else:
                break
        self._undos += 1

        return {
            "undone": target.move_no,
            "color": target.color,
            "kind": target.kind,
            "coord": target.coord,
            "removed": len(removed),
            "moves": len(self._moves),
        }

    # ------------------------------------------------------------------
    # Clocks
    # ------------------------------------------------------------------
    @staticmethod
    def _clock_view(state: dict) -> dict:
        return {
            "main_left": state["main_left"],
            "in_byo_yomi": state["in_byo_yomi"],
            "periods_left": state["periods_left"],
            "period_left": state["period_left"],
            "paused": state["paused"],
        }

    def _charge_clock_locked(
        self, color: str, seconds: int
    ) -> tuple[dict, bool]:
        clock = self._clocks[color]
        if clock["paused"] or seconds <= 0:
            return self._clock_view(clock), False

        if clock["in_byo_yomi"] or clock["main_left"] <= 0:
            clock["main_left"] = 0
            clock["in_byo_yomi"] = True
            if clock["periods_left"] <= 0:
                clock["period_left"] = 0
                return self._clock_view(clock), True

            clock["period_left"] -= seconds
            if clock["period_left"] <= 0:
                clock["periods_left"] -= 1
                if clock["periods_left"] <= 0:
                    clock["periods_left"] = 0
                    clock["period_left"] = 0
                    return self._clock_view(clock), True
                clock["period_left"] = self.byo_yomi
            return self._clock_view(clock), False

        if seconds < clock["main_left"]:
            clock["main_left"] -= seconds
            return self._clock_view(clock), False

        if seconds == clock["main_left"]:
            clock["main_left"] = 0
            clock["in_byo_yomi"] = True
            if clock["periods_left"] <= 0:
                clock["period_left"] = 0
                return self._clock_view(clock), True
            clock["period_left"] = self.byo_yomi
            return self._clock_view(clock), False

        overflow = seconds - clock["main_left"]
        clock["main_left"] = 0
        clock["in_byo_yomi"] = True
        if clock["periods_left"] <= 0:
            clock["period_left"] = 0
            return self._clock_view(clock), True

        clock["period_left"] = self.byo_yomi - overflow
        if clock["period_left"] <= 0:
            clock["periods_left"] -= 1
            if clock["periods_left"] <= 0:
                clock["periods_left"] = 0
                clock["period_left"] = 0
                return self._clock_view(clock), True
            clock["period_left"] = self.byo_yomi
        return self._clock_view(clock), False

    def tick_clock(self, color: str, seconds: int) -> dict:
        """Charge *seconds* to one side's clock."""
        with self._lock:
            try:
                color = self._validated_color(color)
                if type(seconds) is not int or seconds < 0:
                    raise WeiqiError("WEIQI_INVALID_TIME", seconds)
            except WeiqiError:
                self._refused += 1
                raise

            state, timed_out = self._charge_clock_locked(color, seconds)
            if timed_out and not self._game_over:
                self._game_over = True
                self._winner = self._other(color)
                self._end_reason = "timeout"
            return state

    def pause_clock(self, color: str) -> dict:
        """Freeze one side's clock, leaving the other running."""
        with self._lock:
            try:
                color = self._validated_color(color)
            except WeiqiError:
                self._refused += 1
                raise
            self._clocks[color]["paused"] = True
            return self._clock_view(self._clocks[color])

    def resume_clock(self, color: str) -> dict:
        """Release a pause previously taken on one side's clock."""
        with self._lock:
            try:
                color = self._validated_color(color)
            except WeiqiError:
                self._refused += 1
                raise
            self._clocks[color]["paused"] = False
            return self._clock_view(self._clocks[color])

    def clock_state(self, color: str | None = None) -> dict:
        """Report remaining main time and byo-yomi state."""
        with self._lock:
            if color is None:
                return {
                    side: self._clock_view(self._clocks[side])
                    for side in COLORS
                }
            color = self._validated_color(color)
            return self._clock_view(self._clocks[color])

    # ------------------------------------------------------------------
    # Scoring and queries
    # ------------------------------------------------------------------
    def _score_locked(self) -> dict:
        stones = {BLACK: 0, WHITE: 0}
        territory = {BLACK: 0, WHITE: 0}
        visited: set[tuple[int, int]] = set()

        for start_row in range(self.size):
            for start_col in range(self.size):
                cell = self._board[start_row][start_col]
                if cell is not None:
                    stones[cell] += 1
                    continue
                start = (start_row, start_col)
                if start in visited:
                    continue

                region: set[tuple[int, int]] = set()
                borders: set[str] = set()
                stack = [start]
                while stack:
                    current = stack.pop()
                    if current in region:
                        continue
                    region.add(current)
                    visited.add(current)
                    for neighbor in self._neighbors(current):
                        neighbor_cell = self._board[
                            neighbor[0]
                        ][neighbor[1]]
                        if neighbor_cell is None:
                            if neighbor not in region:
                                stack.append(neighbor)
                        else:
                            borders.add(neighbor_cell)

                if len(borders) == 1:
                    territory[next(iter(borders))] += len(region)

        black_total = stones[BLACK] + territory[BLACK]
        white_total = stones[WHITE] + territory[WHITE] + self.komi
        if black_total > white_total:
            winner: str | None = BLACK
        elif white_total > black_total:
            winner = WHITE
        else:
            winner = "draw"

        return {
            "black": {
                "stones": stones[BLACK],
                "territory": territory[BLACK],
                "total": black_total,
            },
            "white": {
                "stones": stones[WHITE],
                "territory": territory[WHITE],
                "total": white_total,
            },
            "komi": self.komi,
            "winner": winner,
        }

    def score(self) -> dict:
        """Area-score the current position (stones plus surrounded points)."""
        with self._lock:
            return self._score_locked()

    def stone_at(self, coord: tuple[int, int]) -> str | None:
        """Return the colour on *coord*, or ``None`` when empty."""
        with self._lock:
            row, col = self._validated_coord(coord)
            return self._board[row][col]

    def captures_of(self, color: str) -> int:
        """Return how many stones *color* has captured so far."""
        with self._lock:
            color = self._validated_color(color)
            return self._captures[color]

    def stones_of(self, color: str) -> tuple[tuple[int, int], ...]:
        """Return the sorted coordinates occupied by *color*."""
        with self._lock:
            color = self._validated_color(color)
            points = [
                (row, col)
                for row in range(self.size)
                for col in range(self.size)
                if self._board[row][col] == color
            ]
            return tuple(sorted(points))

    def move_log(self) -> tuple[MoveRecord, ...]:
        """Return every move in the order it was played."""
        with self._lock:
            return tuple(self._moves)

    def position_hash(self) -> str:
        """Return a stable digest of the current board position."""
        with self._lock:
            return self._hash_board(self._board)

    # ------------------------------------------------------------------
    # Snapshot / restore
    # ------------------------------------------------------------------
    def snapshot(self) -> dict:
        """Return a detached copy of the board, history, clocks and counters."""
        with self._lock:
            return {
                "version": 1,
                "size": self.size,
                "komi": self.komi,
                "main_time": self.main_time,
                "byo_yomi": self.byo_yomi,
                "byo_yomi_periods": self.byo_yomi_periods,
                "board": copy.deepcopy(self._board),
                "moves": [
                    {
                        "move_no": record.move_no,
                        "color": record.color,
                        "kind": record.kind,
                        "coord": (
                            tuple(record.coord)
                            if record.coord is not None
                            else None
                        ),
                        "captured": [
                            tuple(point) for point in record.captured
                        ],
                        "position_hash": record.position_hash,
                    }
                    for record in self._moves
                ],
                "history": list(self._history),
                "history_tail": len(self._history) - (
                    len(self._moves) + 1
                ),
                "captures": dict(self._captures),
                "phantom_captures": {
                    str(move_no): [
                        tuple(point) for point in sorted(points)
                    ]
                    for move_no, points in self._phantom_captures.items()
                },
                "turn": self._next_color,
                "game_over": self._game_over,
                "winner": self._winner,
                "end_reason": self._end_reason,
                "consecutive_passes": self._consecutive_passes,
                "ko_barrier": self._ko_barrier,
                "refused": self._refused,
                "undos": self._undos,
                "clocks": {
                    color: self._clock_view(self._clocks[color])
                    for color in COLORS
                },
            }

    @staticmethod
    def _is_int(value: object) -> bool:
        return type(value) is int

    @staticmethod
    def _is_number(value: object) -> bool:
        return type(value) in (int, float)

    @staticmethod
    def _invalid_snapshot(detail: object) -> None:
        raise WeiqiError("WEIQI_SNAPSHOT_INVALID", detail)

    def restore(self, state: dict) -> None:
        """Load a snapshot after validating its structure."""
        with self._lock:
            self._restore_locked(state)

    def _restore_locked(self, state: dict) -> None:
        if not isinstance(state, dict):
            self._invalid_snapshot("snapshot must be a mapping")

        required = {
            "version",
            "size",
            "komi",
            "main_time",
            "byo_yomi",
            "byo_yomi_periods",
            "board",
            "moves",
            "history",
            "history_tail",
            "captures",
            "turn",
            "game_over",
            "winner",
            "end_reason",
            "consecutive_passes",
            "ko_barrier",
            "refused",
            "undos",
            "clocks",
        }
        if not required.issubset(state):
            self._invalid_snapshot("missing snapshot fields")
        if state["version"] != 1:
            self._invalid_snapshot("unsupported snapshot version")

        size = state["size"]
        if not self._is_int(size) or size <= 0:
            self._invalid_snapshot("invalid size")
        if not self._is_number(state["komi"]):
            self._invalid_snapshot("invalid komi")
        main_time = state["main_time"]
        byo_yomi = state["byo_yomi"]
        periods = state["byo_yomi_periods"]
        if not self._is_int(main_time) or main_time < 0:
            self._invalid_snapshot("invalid main_time")
        if not self._is_int(byo_yomi) or byo_yomi < 0:
            self._invalid_snapshot("invalid byo_yomi")
        if not self._is_int(periods) or periods < 0:
            self._invalid_snapshot("invalid byo_yomi_periods")

        raw_board = state["board"]
        if not isinstance(raw_board, (list, tuple)):
            self._invalid_snapshot("board must be a sequence")
        if len(raw_board) != size:
            self._invalid_snapshot("board size mismatch")
        board: list[list[str | None]] = []
        for raw_row in raw_board:
            if not isinstance(raw_row, (list, tuple)):
                self._invalid_snapshot("board row must be a sequence")
            if len(raw_row) != size:
                self._invalid_snapshot("board row size mismatch")
            row: list[str | None] = []
            for cell in raw_row:
                if cell is not None and cell not in COLORS:
                    self._invalid_snapshot("invalid board point")
                row.append(cell)
            board.append(row)

        raw_moves = state["moves"]
        if not isinstance(raw_moves, (list, tuple)):
            self._invalid_snapshot("moves must be a sequence")
        moves: list[MoveRecord] = []
        capture_totals = {BLACK: 0, WHITE: 0}
        for index, raw_move in enumerate(raw_moves):
            if not isinstance(raw_move, dict):
                self._invalid_snapshot("move must be a mapping")
            if raw_move.get("move_no") != index + 1:
                self._invalid_snapshot("move numbering mismatch")
            move_color = raw_move.get("color")
            if move_color not in COLORS:
                self._invalid_snapshot("invalid move colour")
            kind = raw_move.get("kind")
            if kind not in ("stone", "pass"):
                self._invalid_snapshot("invalid move kind")

            coord_raw = raw_move.get("coord")
            if kind == "pass":
                if coord_raw is not None:
                    self._invalid_snapshot("pass cannot have a coord")
                coord = None
            else:
                if (
                    not isinstance(coord_raw, (tuple, list))
                    or len(coord_raw) != 2
                    or type(coord_raw[0]) is not int
                    or type(coord_raw[1]) is not int
                    or not (
                        0 <= coord_raw[0] < size
                        and 0 <= coord_raw[1] < size
                    )
                ):
                    self._invalid_snapshot("invalid move coord")
                coord = (coord_raw[0], coord_raw[1])

            raw_captured = raw_move.get("captured")
            if not isinstance(raw_captured, (list, tuple)):
                self._invalid_snapshot("captured must be a sequence")
            captured: list[tuple[int, int]] = []
            seen_captured: set[tuple[int, int]] = set()
            for captured_raw in raw_captured:
                if (
                    not isinstance(captured_raw, (tuple, list))
                    or len(captured_raw) != 2
                    or type(captured_raw[0]) is not int
                    or type(captured_raw[1]) is not int
                    or not (
                        0 <= captured_raw[0] < size
                        and 0 <= captured_raw[1] < size
                    )
                ):
                    self._invalid_snapshot("invalid captured coord")
                point = (captured_raw[0], captured_raw[1])
                if point in seen_captured:
                    self._invalid_snapshot("duplicate captured coord")
                seen_captured.add(point)
                captured.append(point)
            if kind == "pass" and captured:
                self._invalid_snapshot("pass cannot capture")
            capture_totals[move_color] += len(captured)

            move_hash = raw_move.get("position_hash")
            if not isinstance(move_hash, str):
                self._invalid_snapshot("invalid move position_hash")
            moves.append(
                MoveRecord(
                    move_no=index + 1,
                    color=move_color,
                    kind=kind,
                    coord=coord,
                    captured=tuple(sorted(captured)),
                    position_hash=move_hash,
                )
            )

        raw_history = state["history"]
        if not isinstance(raw_history, (list, tuple)):
            self._invalid_snapshot("history must be a sequence")
        history_tail = state["history_tail"]
        if not self._is_int(history_tail) or history_tail < 0:
            self._invalid_snapshot("invalid history_tail")
        if len(raw_history) != len(moves) + 1 + history_tail:
            self._invalid_snapshot("history length mismatch")
        if any(not isinstance(item, str) for item in raw_history):
            self._invalid_snapshot("history entries must be strings")
        empty_hash = self._hash_board(
            [[None for _ in range(size)] for _ in range(size)]
        )
        if raw_history[0] != empty_hash:
            self._invalid_snapshot("history does not start empty")
        if raw_history[-1] != self._hash_board(board):
            self._invalid_snapshot("history does not match board")
        if history_tail == 0:
            for index, move in enumerate(moves):
                if move.position_hash != raw_history[index + 1]:
                    self._invalid_snapshot(
                        "move hash does not match history"
                    )

        raw_captures = state["captures"]
        if not isinstance(raw_captures, dict):
            self._invalid_snapshot("captures must be a mapping")
        captures = {}
        for color in COLORS:
            value = raw_captures.get(color)
            if not self._is_int(value) or value < 0:
                self._invalid_snapshot("invalid capture total")
            captures[color] = value
        if history_tail == 0 and captures != capture_totals:
            self._invalid_snapshot("capture totals mismatch")
        if any(
            captures[color] < capture_totals[color] for color in COLORS
        ):
            self._invalid_snapshot("capture totals mismatch")

        raw_phantom = state.get("phantom_captures", {})
        if not isinstance(raw_phantom, dict):
            self._invalid_snapshot("phantom captures must be a mapping")
        phantom_captures: dict[int, frozenset[tuple[int, int]]] = {}
        for raw_move_no, raw_points in raw_phantom.items():
            if isinstance(raw_move_no, str):
                try:
                    move_no = int(raw_move_no)
                except ValueError:
                    self._invalid_snapshot("invalid phantom move number")
            else:
                move_no = raw_move_no
            if not self._is_int(move_no) or move_no < 1:
                self._invalid_snapshot("invalid phantom move number")
            if not isinstance(raw_points, (list, tuple)):
                self._invalid_snapshot("invalid phantom captures")
            points: list[tuple[int, int]] = []
            for raw_point in raw_points:
                if (
                    not isinstance(raw_point, (tuple, list))
                    or len(raw_point) != 2
                    or type(raw_point[0]) is not int
                    or type(raw_point[1]) is not int
                    or not (
                        0 <= raw_point[0] < size
                        and 0 <= raw_point[1] < size
                    )
                ):
                    self._invalid_snapshot("invalid phantom coord")
                points.append((raw_point[0], raw_point[1]))
            phantom_captures[move_no] = frozenset(points)

        turn = state["turn"]
        if turn not in COLORS:
            self._invalid_snapshot("invalid turn")
        if type(state["game_over"]) is not bool:
            self._invalid_snapshot("invalid game_over")
        winner = state["winner"]
        if winner is not None and winner not in (*COLORS, "draw"):
            self._invalid_snapshot("invalid winner")
        end_reason = state["end_reason"]
        if end_reason is not None and not isinstance(end_reason, str):
            self._invalid_snapshot("invalid end_reason")

        consecutive_passes = state["consecutive_passes"]
        if (
            not self._is_int(consecutive_passes)
            or consecutive_passes < 0
        ):
            self._invalid_snapshot("invalid consecutive_passes")
        ko_barrier = state["ko_barrier"]
        if ko_barrier is not None and (
            not self._is_int(ko_barrier)
            or ko_barrier < 0
            or ko_barrier > len(moves)
        ):
            self._invalid_snapshot("invalid ko_barrier")
        refused = state["refused"]
        undos = state["undos"]
        if not self._is_int(refused) or refused < 0:
            self._invalid_snapshot("invalid refused counter")
        if not self._is_int(undos) or undos < 0:
            self._invalid_snapshot("invalid undos counter")

        raw_clocks = state["clocks"]
        if not isinstance(raw_clocks, dict):
            self._invalid_snapshot("clocks must be a mapping")
        clocks = {}
        for color in COLORS:
            raw_clock = raw_clocks.get(color)
            if not isinstance(raw_clock, dict):
                self._invalid_snapshot("missing clock state")
            main_left = raw_clock.get("main_left")
            if not self._is_number(main_left) or main_left < 0:
                self._invalid_snapshot("invalid clock main_left")
            in_byo = raw_clock.get("in_byo_yomi")
            if type(in_byo) is not bool:
                self._invalid_snapshot("invalid clock in_byo_yomi")
            periods_left = raw_clock.get("periods_left")
            if (
                not self._is_int(periods_left)
                or periods_left < 0
                or periods_left > periods
            ):
                self._invalid_snapshot("invalid clock periods_left")
            period_left = raw_clock.get("period_left")
            if (
                not self._is_number(period_left)
                or period_left < 0
                or (byo_yomi and period_left > byo_yomi)
            ):
                self._invalid_snapshot("invalid clock period_left")
            paused = raw_clock.get("paused")
            if type(paused) is not bool:
                self._invalid_snapshot("invalid clock paused")
            clocks[color] = {
                "main_left": main_left,
                "in_byo_yomi": in_byo,
                "periods_left": periods_left,
                "period_left": period_left,
                "paused": paused,
            }

        # Everything has been validated; only now touch live state.
        self.size = size
        self.komi = state["komi"]
        self.main_time = main_time
        self.byo_yomi = byo_yomi
        self.byo_yomi_periods = periods
        self._board = board
        self._moves = moves
        self._captures = captures
        self._phantom_captures = phantom_captures
        self._next_color = turn
        self._history = list(raw_history)
        self._consecutive_passes = consecutive_passes
        self._game_over = state["game_over"]
        self._winner = winner
        self._end_reason = end_reason
        self._ko_barrier = ko_barrier
        self._refused = refused
        self._undos = undos
        self._clocks = clocks

    # ------------------------------------------------------------------
    # Counters
    # ------------------------------------------------------------------
    def stats(self) -> dict:
        """Return cumulative counters for moves, captures and refusals."""
        with self._lock:
            return {
                "moves": len(self._moves),
                "passes": sum(
                    record.kind == "pass" for record in self._moves
                ),
                "captures": dict(self._captures),
                "refused": self._refused,
                "undos": self._undos,
            }
