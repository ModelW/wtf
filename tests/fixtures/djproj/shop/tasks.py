"""Procrastinate tasks of the fixture."""

from procrastinate.contrib.django import app


def setup(app):
    """Nothing to configure; the hook exists so the app is initialised."""


@app.task(name="shop.send_receipt")
def send_receipt(order_id: int):
    """Email the receipt of an order."""


@app.periodic(cron="0 3 * * *")
@app.task(name="shop.purge_carts")
def purge_carts(timestamp: int):
    """Delete abandoned carts."""
