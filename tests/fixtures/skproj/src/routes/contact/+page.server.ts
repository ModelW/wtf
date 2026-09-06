import type { Actions } from "./$types";

export const actions: Actions = {
    send: async ({ request }) => {
        const form = await request.formData();
        const email = form.get("email");
        await fetch("/back/api/contact", { method: "POST", body: JSON.stringify({ email }) });
        return { sent: true };
    },
};
