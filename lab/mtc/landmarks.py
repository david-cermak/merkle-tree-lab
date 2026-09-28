"""The landmark sequence: pre-distributed subtree hashes (Section 6.4).

A landmark is the MTC answer to "what if the client has nothing yet?". A
landmark says: *at tree size N, the log's root hashed to this*. That is a
checkpoint, and a client that has never seen the CA cannot accept it. So a CA
that wants small certificates has to get a value into clients' hands *before*
the handshake, out of band, and Section 6.4.1 turns that value into something
small enough to keep: instead of one hash per landmark, clients keep the
**landmark subtrees**, of which there are exactly two per landmark.

Those two are not chosen, they are *derived*: they are the two subtrees that
cover the range between this landmark's tree size and the previous landmark's
(Section 6.4.1 step 3, which is Section 4.5's covering algorithm again). With
landmark 0 pinned at tree size zero, landmark 1 in a 20-entry log has subtrees
``[0, 16)`` and ``[16, 20)`` -- the first 16 entries hash to one value, the
last 4 to another, and a client that stored those two values can validate a
certificate for *any* entry in the log without a signature.

That is the whole trick, and it is worth being precise about the two halves of
it:

* the *proof* in the certificate is logarithmic in the subtree, so a bigger
  landmark means a slightly bigger certificate (Section 6.5: 12 hashes for a
  2-second checkpoint cadence, 23 for hourly landmarks, 32 for subtrees up to
  2^32);
* the *signatures* are gone entirely, which is where the 2 420 bytes of an
  ML-DSA-44 cosignature go. That is the real prize, and it is only available
  because the client already trusts a hash.

Section 6.4.1 also fixes the properties the sequence must have, and this module
enforces them on append: tree sizes strictly increase, expiry times never
decrease, and landmark 0 is ``(0, 0)``. A CA that gets the sequence wrong breaks
availability, not security -- "Mistakes in landmark sequence allocation only
impact availability, not security" -- and :meth:`LandmarkSequence.check` is how
the lab demonstrates that: it reports the mistake instead of accepting it.

Section 6.4.3's publication format is the wire form of a client's state, and
:func:`publish` / :func:`parse_publication` implement it strictly, because the
draft's decoder rules ("MUST reject documents that do not strictly conform")
are the interesting part: an expired landmark has to appear in the document, so
a client can tell where the active ones stop.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Sequence, Tuple

from .log import LAB_EPOCH
from .tree import find_subtrees, is_valid_subtree, subtree_hash

Subtree = Tuple[int, int]


@dataclass(frozen=True)
class Landmark:
    """One landmark: a number, a tree size, an expiry, and its two subtrees.

    ``expiry`` is seconds since the Epoch. A landmark that is not yet expired
    is *active* (Section 6.4.1), and its subtrees are what a client holds.
    """

    number: int
    tree_size: int
    expiry: int
    subtrees: Tuple[Subtree, Subtree]

    def contains(self, index: int) -> bool:
        """Return ``True`` if ``index`` falls in one of the landmark's subtrees."""
        return any(start <= index < end for start, end in self.subtrees)

    def subtree_for(self, index: int) -> Subtree:
        """Return the unique subtree containing ``index``.

        Section 6.4.4 step 3: "select the unique one whose [start, end)
        interval contains idx". The pair covers a contiguous range, so
        uniqueness holds -- but only for indices in range, which is why
        :meth:`contains` is checked first.
        """
        for subtree in self.subtrees:
            if subtree[0] <= index < subtree[1]:
                return subtree
        raise ValueError(f"index {index} is in no subtree of landmark {self.number}")

    def __str__(self) -> str:
        pairs = ", ".join(f"[{start}, {end})" for start, end in self.subtrees)
        return f"landmark {self.number} (size {self.tree_size}, expires {self.expiry}): {pairs}"


def allocate(
    sequence: "LandmarkSequence",
    tree_size: int,
    expiry: int,
) -> Landmark:
    """Append a landmark, deriving its subtrees from the previous one.

    This is step 4 of the recommended procedure in Section 6.4.2. The caller
    decides *when* to allocate -- once per time interval, and not at all if the
    tree size has not moved -- and this function enforces the monotonicity that
    Section 6.4.1 requires and derives the two landmark subtrees.
    """
    return sequence.append(tree_size, expiry)


class LandmarkSequence:
    """An append-only sequence of landmarks for one issuance log."""

    def __init__(self, log_id=None) -> None:
        # Landmark 0 is special: tree size zero, expiry zero, and two empty
        # subtrees. It exists so that landmark 1's subtrees have a predecessor
        # to cover from, and it is never active.
        self.log_id = log_id
        self.landmarks: List[Landmark] = [
            Landmark(
                number=0,
                tree_size=0,
                expiry=0,
                subtrees=((0, 0), (0, 0)),
            )
        ]

    def __len__(self) -> int:
        return len(self.landmarks)

    def __iter__(self):
        return iter(self.landmarks)

    def __getitem__(self, number: int) -> Landmark:
        return self.landmarks[number]

    @property
    def latest(self) -> Landmark:
        return self.landmarks[-1]

    def append(self, tree_size: int, expiry: int) -> Landmark:
        """Append a landmark and return it.

        Raises ``ValueError`` if the append would break the Section 6.4.1
        invariants: a tree size that does not strictly increase, or an expiry
        that goes backwards.
        """
        previous = self.latest
        if tree_size <= previous.tree_size:
            raise ValueError(
                f"landmark tree size must increase: {tree_size} after {previous.tree_size}"
            )
        if expiry < previous.expiry:
            raise ValueError(
                f"landmark expiry must not decrease: {expiry} before {previous.expiry}"
            )
        subtrees = landmark_subtrees(previous.tree_size, tree_size)
        landmark = Landmark(
            number=previous.number + 1,
            tree_size=tree_size,
            expiry=expiry,
            subtrees=subtrees,
        )
        self.landmarks.append(landmark)
        return landmark

    def active(self, now: int) -> List[Landmark]:
        """Return the landmarks that have not expired at ``now`` (Section 6.4.1).

        Landmark 0 is never active, so it is skipped.
        """
        return [lm for lm in self.landmarks if lm.number > 0 and lm.expiry > now]

    def lowest_above(self, index: int, now: Optional[int] = None) -> Optional[Landmark]:
        """Return the lowest-numbered *active* landmark whose size exceeds ``index``.

        This is step 2 of Section 6.4.4: the landmark a landmark-relative
        certificate for ``index`` waits for. "Lowest numbered" rather than
        "newest" is deliberate -- the client may already trust that landmark, so
        using an older one costs nothing and may cost no extra client state
        either. Only active landmarks are considered, because an expired
        landmark's subtrees may no longer be accepted.
        """
        for landmark in self.active(self._clock(now)):
            if landmark.tree_size > index:
                return landmark
        return None

    def covers(self, index: int, now: Optional[int] = None) -> bool:
        """Return ``True`` if some active landmark's subtrees cover ``index``.

        Section 6.4.1: "every unexpired entry in the log is either contained in
        some landmark subtree or was allocated sometime after the latest
        landmark". This checks the first half, at ``now`` or at the latest
        landmark's expiry if no time is given.
        """
        return any(landmark.contains(index) for landmark in self.active(self._clock(now)))

    def check(self) -> List[str]:
        """Return a list of invariant violations, empty if the sequence is sound.

        The draft's own words (Section 6.4.1) are that landmark mistakes "only
        impact availability, not security", so this reports rather than raises:
        a client that sees a violation rejects the affected certificates, but it
        does not accept anything the CA did not certify.
        """
        problems: List[str] = []
        zero = self.landmarks[0]
        if zero.tree_size != 0 or zero.expiry != 0:
            problems.append("landmark 0 must have tree size 0 and expiry 0")
        for earlier, later in zip(self.landmarks, self.landmarks[1:]):
            if later.tree_size <= earlier.tree_size:
                problems.append(
                    f"landmark {later.number} tree size {later.tree_size} "
                    f"does not exceed landmark {earlier.number} ({earlier.tree_size})"
                )
            if later.expiry < earlier.expiry:
                problems.append(
                    f"landmark {later.number} expiry {later.expiry} "
                    f"is before landmark {earlier.number} ({earlier.expiry})"
                )
            if later.number != earlier.number + 1:
                problems.append(f"landmark numbering skips at {later.number}")
        return problems

    def _clock(self, now: Optional[int]) -> int:
        """Return ``now``, or a self-consistent default if none was given.

        Landing on the latest expiry is the only time the whole sequence is
        active at once, so it is the only clock at which a landmark-relative
        certificate is guaranteed to have a landmark to wait for.
        """
        return self.latest.expiry if now is None else now

    def __str__(self) -> str:
        return f"landmark sequence of {len(self.landmarks)} landmarks, latest {self.latest}"


def landmark_subtrees(previous_tree_size: int, tree_size: int) -> Tuple[Subtree, Subtree]:
    """Return the two subtrees covering ``[previous_tree_size, tree_size)``.

    Section 6.4.1 step 3. Landmark 0 is the degenerate case: both subtrees are
    ``[0, 0)``, and no real interval is involved.
    """
    if tree_size <= previous_tree_size:
        raise ValueError(
            f"tree size {tree_size} must exceed the previous landmark's {previous_tree_size}"
        )
    return find_subtrees(previous_tree_size, tree_size)


def subtree_hashes_for(
    sequence: LandmarkSequence, leaf_hashes: Sequence[bytes], now: Optional[int] = None
) -> List[dict]:
    """Return the client-side state: one row per *active* landmark subtree.

    This is what a relying party stores (Section 7.4) -- the log ID, the
    interval, and the hash -- and it is the input the landmark-relative
    verification path compares against.

    "Active" is the draft's own restriction: "Trusted subtrees for a CA are
    determined by its active landmark subtrees." A landmark past its expiry is
    skipped, because a relying party that keeps trusting one indefinitely has
    turned a time-bounded prediction into a permanent one.

    ``now`` defaults to ``LAB_EPOCH``, the lab's fixed clock: the moment the log
    was built, when everything allocated in it is still active. A caller
    replaying a later moment has to say so, which is the point -- the expiry is
    what stops being ignored.
    """
    if now is None:
        now = LAB_EPOCH
    rows: List[dict] = []
    for landmark in sequence.active(now):
        for start, end in landmark.subtrees:
            if start == end:
                continue
            if not is_valid_subtree(start, end):
                raise ValueError(f"landmark {landmark.number} produced invalid {start, end}")
            rows.append(
                {
                    "log_id": sequence.log_id,
                    "landmark": landmark.number,
                    "start": start,
                    "end": end,
                    "hash": subtree_hash(leaf_hashes, start, end),
                }
            )
    return rows


def publish(sequence: LandmarkSequence, now: int) -> str:
    """Render the active landmarks in the Section 6.4.3 publication format.

    The format is a header line carrying ``latest_landmark``, then
    ``num_active_landmarks + 1`` lines, newest landmark first, each
    ``tree_size expiry``. The extra line is the first *expired* landmark, which
    the format requires: it is how a decoder knows where the active landmarks
    stop. Landmark 0 (tree size 0, expiry 0) is always expired, so the walk
    always terminates.
    """
    lines = [str(sequence.latest.number)]
    for landmark in reversed(sequence.landmarks):
        lines.append(f"{landmark.tree_size} {landmark.expiry}")
        if landmark.number == 0 or landmark.expiry <= now:
            break
    return "".join(line + "\n" for line in lines)


def parse_publication(document: str, now: int) -> List[Landmark]:
    """Parse the Section 6.4.3 publication format into landmark rows.

    Returns the landmarks that were published, oldest first, stopping at the
    first expired one. The draft's decoder rules are strict -- no stray
    whitespace, tree sizes strictly decreasing down the document, expiries
    monotonically decreasing, and at least one expired landmark present -- and
    this raises rather than guessing when they are not met.
    """
    if not document.endswith("\n"):
        raise ValueError("publication must end with a newline")
    lines = document.split("\n")[:-1]
    if not lines:
        raise ValueError("publication is empty")
    try:
        latest = int(lines[0])
    except ValueError as exc:
        raise ValueError(f"latest_landmark is not an integer: {lines[0]!r}") from exc
    if latest < 0:
        raise ValueError("latest_landmark must not be negative")

    landmarks: List[Landmark] = []
    for offset, line in enumerate(lines[1:]):
        number = latest - offset
        if number < 0:
            raise ValueError("publication has more landmark lines than latest_landmark")
        if line.count(" ") != 1 or line != line.strip():
            raise ValueError(f"malformed landmark line: {line!r}")
        size_text, expiry_text = line.split(" ")
        if not size_text.isdigit() or not expiry_text.isdigit():
            raise ValueError(f"malformed landmark line: {line!r}")
        landmarks.append(
            Landmark(
                number=number,
                tree_size=int(size_text),
                expiry=int(expiry_text),
                subtrees=((0, 0), (0, 0)),
            )
        )

    if not landmarks:
        raise ValueError("publication has no landmark lines")
    for earlier, later in zip(landmarks, landmarks[1:]):
        if later.tree_size >= earlier.tree_size:
            raise ValueError("tree sizes must strictly decrease down the document")
        if later.expiry > earlier.expiry:
            raise ValueError("expiration times must monotonically decrease")
    if landmarks[-1].expiry > now:
        raise ValueError("publication must include at least one expired landmark")
    return landmarks
