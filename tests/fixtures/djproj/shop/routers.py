"""Send the audit model to its own database (exercises store slugs)."""


class AuditRouter:
    """``shop.AuditEntry`` lives in ``audit``; everything else in ``default``."""

    def db_for_write(self, model, **hints):
        return "audit" if model.__name__ == "AuditEntry" else None

    db_for_read = db_for_write
