"""A Django Ninja API with a typed request/response pair."""

from uuid import UUID

from ninja import NinjaAPI, Router, Schema

api = NinjaAPI(urls_namespace="api")
router = Router()


class CheckoutIn(Schema):
    cart_id: UUID
    email: str
    delivery_instructions: str | None = None


class CheckoutOut(Schema):
    reference: str
    total: str


@router.post("/checkout", response=CheckoutOut, operation_id="checkout")
def checkout(request, payload: CheckoutIn):
    """Create an order from a cart."""
    from shop.tasks import send_receipt

    send_receipt.defer(order_id=1)
    return CheckoutOut(reference="R1", total="10.00")


@router.get("/customers/{customer_id}", operation_id="getCustomer")
def get_customer(request, customer_id: int, verbose: bool = False):
    return {"id": customer_id}


api.add_router("/shop", router)
