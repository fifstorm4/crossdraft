# Notices

## Licence

CrossDraft is distributed under the GNU General Public License, version 3
or later. The full text is in `LICENSE`.

GPLv3 is not a preference here, it is a consequence. The netlist extractor
links against `Digital.jar`, and the analysis side imports CLAASP; both are
GPLv3, as is SageMath underneath CLAASP. Anything distributed with them
inherits the licence.

| Component | Licence | Used for |
|---|---|---|
| [Digital](https://github.com/hneemann/Digital) | GPLv3 | schematic capture, simulation, netlist resolution |
| [CLAASP](https://github.com/Crypto-TII/claasp) | GPLv3 | differential and linear models |
| SageMath / passagemath | GPLv3 | CLAASP's mathematics |
| [Kissat](https://github.com/arminbiere/kissat) | MIT | SAT solving |
| [espresso](https://github.com/classabbyamp/espresso-logic) | MIT (Berkeley) | S-box constraint generation |
| NIST STS 2.1.2 | public domain (US Government work) | statistical tests |

None of these are bundled in this repository. `setup_nist.py` and the
Dockerfile fetch them; the licences above are the upstream projects' own.

## Development with AI assistance

Portions of this software were developed with the assistance of a large
language model. All design decisions, verification results, and correctness
claims were reviewed and validated by the author.

This is a methodological disclosure rather than an attribution of
authorship: a language model cannot hold authorship or take responsibility
for the work, so the human author does.

It is worth saying what that validation consisted of, because the point is
not that the code was reviewed by eye. `tests/test_fuzz.py` generates random
circuits and requires Digital's own simulator to agree with this project's
evaluator; it found six real defects, and four of them were in code that had
already passed a hand-written suite. The claim this project makes is not
that its code was written carefully. It is that its results are checked
against an independent implementation, every time.
