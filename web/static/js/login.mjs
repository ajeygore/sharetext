// Development sign-in only. The Google button is a plain link and needs no JS.
const form = document.getElementById("dev-login");
if (form) {
  const base = document.querySelector("main")?.dataset.base ?? "";
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    await fetch(`${base}/auth/dev-login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify({ email: document.getElementById("devEmail").value }),
    });
    location.href = location.pathname;
  });
}
