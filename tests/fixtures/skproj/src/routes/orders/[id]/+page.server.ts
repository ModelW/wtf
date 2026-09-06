import type { PageServerLoad } from "./$types";

export const load: PageServerLoad = async ({ params }) => {
  const order = await api.orders.getOrder(params.id);
  return { order: { reference: order.reference as string, customerEmail: order.email as string, total: 12 } };
};

declare const api: { orders: { getOrder(id: string): Promise<Record<string, unknown>> } };
