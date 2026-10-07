import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import { startTestApp } from "./test-app.mjs";

let app;
before(async () => { app = await startTestApp({ port: 0 }); });
after(() => app.close());

const post = (p, fields) =>
  fetch(app.url + p, {
    method: "POST",
    redirect: "manual",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(fields),
  });

const PW = "S3cret-pw-xyzzy-12345";

test("register, login, and no response echoes the password", async () => {
  const bodies = [];
  const reg = await post("/register", { username: "alice@example.test", password: PW, confirm: PW });
  bodies.push(await reg.text());
  assert.equal(reg.status, 302);
  assert.ok(app.users.get("alice@example.test").hash.length > 0);

  const ok = await post("/login", { username: "alice@example.test", password: PW });
  bodies.push(await ok.text());
  assert.equal(ok.status, 302);
  const loc = ok.headers.get("location");
  assert.equal(loc, "/welcome?u=alice%40example.test");
  const welcome = await (await fetch(app.url + loc)).text();
  bodies.push(welcome);
  assert.match(welcome, /Signed in as alice@example\.test/);

  const bad = await post("/login", { username: "alice@example.test", password: PW + "x" });
  bodies.push(await bad.text());
  assert.equal(bad.status, 401);

  const mismatch = await post("/register", { username: "bob", password: PW, confirm: PW + "x" });
  bodies.push(await mismatch.text());
  assert.equal(mismatch.status, 400);
  assert.equal(app.users.has("bob"), false);

  const dup = await post("/register", { username: "alice@example.test", password: PW, confirm: PW });
  bodies.push(await dup.text());
  assert.equal(dup.status, 409);

  for (const g of ["/register", "/login"]) bodies.push(await (await fetch(app.url + g)).text());
  for (const b of bodies) assert.ok(!b.includes(PW));
});

test("welcome page escapes the username", async () => {
  const html = await (await fetch(app.url + "/welcome?u=" + encodeURIComponent("<script>x</script>"))).text();
  assert.ok(!html.includes("<script>x"));
});
