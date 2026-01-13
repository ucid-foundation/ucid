UCID arXiv Submission Package (v3, 2026-01-13)

Contents
- main.tex
  Two-column LaTeX source (recommended entry point for compilation and arXiv upload).
- UCID_TemporalSpatial_UrbanContextIdentifier_arXiv_20260113.tex
  Same LaTeX source as main.tex, provided under a descriptive filename.
- bibliography.bib
  BibTeX database (academic entries only: @article and @book).
- figures/
  Result figures (vector PDFs).

Build (PDFLaTeX + BibTeX)
1) pdflatex main.tex
2) bibtex main
3) pdflatex main.tex
4) pdflatex main.tex

Notes
- Numeric citations are enabled (classic [1], [2], ... style) and the reference list is ordered by first citation.
- Column separation rule is enabled to display a vertical line between columns.
