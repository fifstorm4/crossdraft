"""Import before claasp when running on passagemath.

sage.rings.integer_ring and sage.rings.integer initialise each other, so
whichever claasp reaches first fails with a circular-import error.  Importing
them here, in this order, lets each finish on its own terms.  Harmless with a
full Sage installation, and harmless when neither is present.
"""
try:
    import sage.rings.integer       # noqa: F401  (order matters)
    import sage.rings.integer_ring  # noqa: F401
except ImportError:
    pass
