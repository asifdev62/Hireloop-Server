/**
 * Security smoke test for the HireLoop Express API.
 *
 * It creates clearly-marked temporary users/sessions/jobs/applications in the
 * database, runs the checks, and deletes everything in a `finally` block.
 *
 * Run from hireloop-server:
 *   npm run test:security
 *
 * Requires the same .env as the API (MONGODB_URL). It starts its own API
 * process on port 5099, so it does not touch a running dev server.
 */

import { spawn } from "node:child_process"
import { randomBytes, randomUUID } from "node:crypto"
import path from "node:path"
import { fileURLToPath } from "node:url"

import dotenv from "dotenv"
import { MongoClient, ObjectId } from "mongodb"
import assert from "node:assert/strict"

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const serverRoot = path.resolve(__dirname, "..")

dotenv.config({ path: path.join(serverRoot, ".env") })

if (!process.env.MONGODB_URL) {
  console.error("MONGODB_URL is required")
  process.exit(1)
}

const PORT = 5099
const BASE_URL = `http://127.0.0.1:${PORT}`
const TEST_TAG = `sec-test-${randomUUID()}`
const TEST_EMAIL_DOMAIN = "example.invalid"

const client = new MongoClient(process.env.MONGODB_URL, {
  serverSelectionTimeoutMS: 15_000,
})

const created = {
  userIds: [],
  sessionTokens: [],
  jobIds: [],
  applicationIds: [],
}

const results = []

function record(name, status, detail = "") {
  results.push({ name, status, detail })
  const icon = status === "PASS" ? "PASS" : status === "FAIL" ? "FAIL" : "SKIP"
  console.log(`[${icon}] ${name}${detail ? ` — ${detail}` : ""}`)
}

async function check(name, fn) {
  try {
    await fn()
    record(name, "PASS")
  } catch (error) {
    record(name, "FAIL", error.message)
  }
}

function newToken() {
  return randomBytes(32).toString("hex")
}

function jsonHeaders(token) {
  return {
    "Content-Type": "application/json",
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  }
}

async function request(pathname, { method = "GET", token, body, origin } = {}) {
  const headers = jsonHeaders(token)
  if (origin) headers.Origin = origin

  const response = await fetch(`${BASE_URL}${pathname}`, {
    method,
    headers,
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  })

  let data = null
  try {
    data = await response.json()
  } catch {
    data = null
  }

  return { status: response.status, data, headers: response.headers }
}

async function waitForServer() {
  const deadline = Date.now() + 30_000

  while (Date.now() < deadline) {
    try {
      const response = await fetch(`${BASE_URL}/`)
      if (response.ok) return
    } catch {
      // not ready yet
    }
    await new Promise((resolve) => setTimeout(resolve, 400))
  }

  throw new Error("API did not start in time")
}

function jobBody(overrides = {}) {
  return {
    title: `${TEST_TAG} Engineer`,
    companyName: "Security Test Co",
    category: "Engineering & Tech",
    location: "Dhaka",
    deadline: "2030-12-31",
    minSalary: 1000,
    maxSalary: 2000,
    salaryFrequency: "per month",
    responsibilities: "Test responsibilities",
    qualifications: "Test qualifications",
    jobType: "Full-time",
    isRemote: true,
    ...overrides,
  }
}

let serverProcess = null

try {
  await client.connect()
  const db = client.db("hireloopdb")
  const users = db.collection("user")
  const sessions = db.collection("session")
  const jobs = db.collection("jobs")
  const applications = db.collection("applications")

  // ---------------------------------------------------------------- fixtures
  const now = new Date()
  const future = new Date(Date.now() + 60 * 60 * 1000)

  async function createUser(role, suffix) {
    const _id = new ObjectId()
    const email = `${TEST_TAG}-${suffix}@${TEST_EMAIL_DOMAIN}`

    await users.insertOne({
      _id,
      name: `Test ${suffix}`,
      email,
      role,
      premium: true,
      emailVerified: true,
      banned: false,
      createdAt: now,
      updatedAt: now,
    })

    created.userIds.push(_id)
    return { id: _id.toString(), email }
  }

  async function createSession(userId, expiresAt = future) {
    const token = newToken()

    await sessions.insertOne({
      _id: new ObjectId(),
      token,
      userId: new ObjectId(userId),
      expiresAt,
      createdAt: now,
      updatedAt: now,
      ipAddress: "127.0.0.1",
      userAgent: "security-smoke-test",
    })

    created.sessionTokens.push(token)
    return token
  }

  const seeker = await createUser("seeker", "seeker")
  const seeker2 = await createUser("seeker", "seeker2")
  const recruiterA = await createUser("recruiter", "recruiter-a")
  const recruiterB = await createUser("recruiter", "recruiter-b")
  const admin = await createUser("admin", "admin")

  const seekerToken = await createSession(seeker.id)
  const seeker2Token = await createSession(seeker2.id)
  const recruiterAToken = await createSession(recruiterA.id)
  const recruiterBToken = await createSession(recruiterB.id)
  const adminToken = await createSession(admin.id)
  const expiredToken = await createSession(
    seeker.id,
    new Date(Date.now() - 60 * 1000)
  )

  const jobAId = new ObjectId()
  const jobBId = new ObjectId()

  await jobs.insertMany([
    {
      _id: jobAId,
      ...jobBody({ title: `${TEST_TAG} Job A` }),
      recruiterId: recruiterA.id,
      recruiterEmail: recruiterA.email,
      createdAt: now.toISOString(),
    },
    {
      _id: jobBId,
      ...jobBody({ title: `${TEST_TAG} Job B` }),
      recruiterId: recruiterB.id,
      recruiterEmail: recruiterB.email,
      createdAt: now.toISOString(),
    },
  ])
  created.jobIds.push(jobAId, jobBId)

  // An application that already exists on recruiter B's job.
  const appBId = new ObjectId()
  await applications.insertOne({
    _id: appBId,
    userId: seeker2.id,
    applicantName: "Test seeker2",
    applicantEmail: seeker2.email,
    jobId: jobBId.toString(),
    jobTitle: `${TEST_TAG} Job B`,
    companyName: "Security Test Co",
    jobType: "Full-time",
    location: "Dhaka",
    isRemote: true,
    status: "Applied",
    appliedAt: now.toISOString(),
    archived: false,
  })
  created.applicationIds.push(appBId)

  // ---------------------------------------------------------------- start API
  serverProcess = spawn(process.execPath, ["index.js"], {
    cwd: serverRoot,
    env: { ...process.env, PORT: String(PORT) },
    stdio: ["ignore", "pipe", "pipe"],
  })

  serverProcess.stderr.on("data", (chunk) => {
    const text = chunk.toString()
    if (!text.includes("ExperimentalWarning")) process.stderr.write(text)
  })

  await waitForServer()

  // ---------------------------------------------------------------- auth tests
  await check("Missing token: GET /jobs/count -> 401", async () => {
    const res = await request("/jobs/count")
    assert.equal(res.status, 401)
  })

  await check("Missing token: POST /jobs -> 401", async () => {
    const res = await request("/jobs", { method: "POST", body: jobBody() })
    assert.equal(res.status, 401)
  })

  await check("Missing token: GET /applications -> 401", async () => {
    const res = await request("/applications")
    assert.equal(res.status, 401)
  })

  await check("Missing token: GET /users -> 401", async () => {
    const res = await request("/users")
    assert.equal(res.status, 401)
  })

  await check("Missing token: PATCH /users/:id/role -> 401", async () => {
    const res = await request(`/users/${seeker.id}/role`, {
      method: "PATCH",
      body: { role: "admin" },
    })
    assert.equal(res.status, 401)
  })

  await check("Missing token: POST /applications -> 401", async () => {
    const res = await request("/applications", {
      method: "POST",
      body: { jobId: jobAId.toString() },
    })
    assert.equal(res.status, 401)
  })

  await check("Missing token: POST /payments/checkout-verify -> 401", async () => {
    const res = await request("/payments/checkout-verify", {
      method: "POST",
      body: { sessionId: "cs_test_fake_session" },
    })
    assert.equal(res.status, 401)
  })

  await check("Invalid token -> 401", async () => {
    const res = await request("/applications", {
      token: "a".repeat(64),
    })
    assert.equal(res.status, 401)
  })

  await check("Expired token -> 401", async () => {
    const res = await request("/applications", { token: expiredToken })
    assert.equal(res.status, 401)
  })

  // ---------------------------------------------------------------- validation
  await check("Invalid job id -> 400", async () => {
    const res = await request("/jobs/not-an-object-id")
    assert.equal(res.status, 400)
  })

  await check("Unknown job id -> 404", async () => {
    const res = await request(`/jobs/${new ObjectId().toString()}`)
    assert.equal(res.status, 404)
  })

  await check("Recruiter delete with invalid id -> 400", async () => {
    const res = await request("/jobs/not-an-object-id", {
      method: "DELETE",
      token: recruiterAToken,
    })
    assert.equal(res.status, 400)
  })

  await check("NoSQL injection in search is neutralised -> 200", async () => {
    const res = await request(
      "/jobs?search[$ne]=x&category=.*&recruiterId[$ne]=x"
    )
    assert.equal(res.status, 200)
  })

  // ---------------------------------------------------------------- seeker RBAC
  await check("Seeker cannot create a job -> 403", async () => {
    const res = await request("/jobs", {
      method: "POST",
      token: seekerToken,
      body: jobBody(),
    })
    assert.equal(res.status, 403)
  })

  await check("Seeker cannot list all users -> 403", async () => {
    const res = await request("/users", { token: seekerToken })
    assert.equal(res.status, 403)
  })

  await check("Seeker cannot change a role -> 403", async () => {
    const res = await request(`/users/${seeker.id}/role`, {
      method: "PATCH",
      token: seekerToken,
      body: { role: "admin" },
    })
    assert.equal(res.status, 403)
  })

  let appAId = null

  await check("Seeker applies with spoofed identity -> identity from session", async () => {
    const res = await request("/applications", {
      method: "POST",
      token: seekerToken,
      body: {
        jobId: jobAId.toString(),
        userId: recruiterB.id,
        applicantEmail: "attacker@example.invalid",
        status: "Offered",
      },
    })
    // Unexpected fields are rejected by the strict schema.
    assert.equal(res.status, 400)
  })

  await check("Seeker applies to job A -> 201", async () => {
    const res = await request("/applications", {
      method: "POST",
      token: seekerToken,
      body: { jobId: jobAId.toString() },
    })
    assert.equal(res.status, 201)
    assert.ok(res.data.insertedId)
    appAId = res.data.insertedId
    created.applicationIds.push(new ObjectId(appAId))
  })

  await check("Application identity comes from the session", async () => {
    const app = await applications.findOne({ _id: new ObjectId(appAId) })
    assert.equal(app.userId, seeker.id)
    assert.equal(app.applicantEmail, seeker.email)
    assert.equal(app.status, "Applied")
    assert.equal(app.jobTitle, `${TEST_TAG} Job A`)
  })

  await check("Duplicate application -> 409", async () => {
    const res = await request("/applications", {
      method: "POST",
      token: seekerToken,
      body: { jobId: jobAId.toString() },
    })
    assert.equal(res.status, 409)
  })

  await check("Seeker cannot read another applicant's rows", async () => {
    const res = await request(
      `/applications?applicantId=${encodeURIComponent(recruiterB.id)}`,
      { token: seekerToken }
    )
    assert.equal(res.status, 200)
    assert.ok(Array.isArray(res.data))
    assert.ok(res.data.every((row) => row.userId === seeker.id))
  })

  await check("Seeker cannot change an application status -> 403", async () => {
    const res = await request(`/applications/${appAId}`, {
      method: "PATCH",
      token: seekerToken,
      body: { status: "Offered" },
    })
    assert.equal(res.status, 403)
  })

  await check("Seeker cannot delete a job -> 403", async () => {
    const res = await request(`/jobs/${jobAId.toString()}`, {
      method: "DELETE",
      token: seekerToken,
    })
    assert.equal(res.status, 403)
  })

  // ---------------------------------------------------------------- recruiter ownership
  let createdJobId = null

  await check("Recruiter cannot spoof recruiterId on create -> 400", async () => {
    const res = await request("/jobs", {
      method: "POST",
      token: recruiterAToken,
      body: jobBody({ recruiterId: recruiterB.id }),
    })
    assert.equal(res.status, 400)
  })

  await check("Recruiter creates a job -> owner from session", async () => {
    const res = await request("/jobs", {
      method: "POST",
      token: recruiterAToken,
      body: jobBody({ title: `${TEST_TAG} Created by A` }),
    })
    assert.equal(res.status, 201)
    createdJobId = res.data.insertedId
    created.jobIds.push(new ObjectId(createdJobId))

    const job = await jobs.findOne({ _id: new ObjectId(createdJobId) })
    assert.equal(job.recruiterId, recruiterA.id)
  })

  await check("Recruiter A cannot delete recruiter B's job -> 404", async () => {
    const res = await request(`/jobs/${jobBId.toString()}`, {
      method: "DELETE",
      token: recruiterAToken,
    })
    assert.equal(res.status, 404)

    const stillThere = await jobs.findOne({ _id: jobBId })
    assert.ok(stillThere, "recruiter B's job must still exist")
  })

  await check("Recruiter A can delete its own job -> 200", async () => {
    const res = await request(`/jobs/${createdJobId}`, {
      method: "DELETE",
      token: recruiterAToken,
    })
    assert.equal(res.status, 200)
    assert.equal(res.data.deletedCount, 1)
  })

  await check("Recruiter A sees only its own job applications", async () => {
    const res = await request("/applications", { token: recruiterAToken })
    assert.equal(res.status, 200)
    assert.ok(Array.isArray(res.data))
    assert.ok(res.data.every((row) => row.jobId === jobAId.toString()))
    assert.ok(!res.data.some((row) => row.jobId === jobBId.toString()))
  })

  await check("Recruiter B cannot change A's application -> 404", async () => {
    const res = await request(`/applications/${appAId}`, {
      method: "PATCH",
      token: recruiterBToken,
      body: { status: "Offered" },
    })
    assert.equal(res.status, 404)
  })

  await check("Recruiter A can change its own application -> 200", async () => {
    const res = await request(`/applications/${appAId}`, {
      method: "PATCH",
      token: recruiterAToken,
      body: { status: "Shortlisted" },
    })
    assert.equal(res.status, 200)
    assert.equal(res.data.status, "Shortlisted")
  })

  await check("Invalid application status -> 400", async () => {
    const res = await request(`/applications/${appAId}`, {
      method: "PATCH",
      token: recruiterAToken,
      body: { status: "Hacked" },
    })
    assert.equal(res.status, 400)
  })

  await check("Recruiter cannot apply to a job -> 403", async () => {
    const res = await request("/applications", {
      method: "POST",
      token: recruiterAToken,
      body: { jobId: jobBId.toString() },
    })
    assert.equal(res.status, 403)
  })

  // ---------------------------------------------------------------- admin
  await check("Admin lists users without sensitive fields -> 200", async () => {
    const res = await request("/users", { token: adminToken })
    assert.equal(res.status, 200)
    assert.ok(Array.isArray(res.data))
    const sample = res.data[0]
    assert.ok(sample)
    assert.equal(sample.password, undefined)
    assert.equal(sample.account, undefined)
  })

  await check("Admin changes a user role -> 200", async () => {
    const res = await request(`/users/${seeker.id}/role`, {
      method: "PATCH",
      token: adminToken,
      body: { role: "recruiter" },
    })
    assert.equal(res.status, 200)
    assert.equal(res.data.modifiedCount, 1)
  })

  await check("Admin cannot remove their own admin role -> 400", async () => {
    const res = await request(`/users/${admin.id}/role`, {
      method: "PATCH",
      token: adminToken,
      body: { role: "seeker" },
    })
    assert.equal(res.status, 400)
  })

  await check("Invalid role is rejected -> 400", async () => {
    const res = await request(`/users/${seeker.id}/role`, {
      method: "PATCH",
      token: adminToken,
      body: { role: "superadmin" },
    })
    assert.equal(res.status, 400)
  })

  await check("Admin can delete any job -> 200", async () => {
    const res = await request(`/jobs/${jobBId.toString()}`, {
      method: "DELETE",
      token: adminToken,
    })
    assert.equal(res.status, 200)
  })

  // ---------------------------------------------------------------- CORS
  await check("Untrusted origin gets no CORS allow header", async () => {
    const res = await request("/jobs", { origin: "https://evil.example" })
    assert.equal(res.headers.get("access-control-allow-origin"), null)
  })

  await check("Trusted origin gets a CORS allow header", async () => {
    const res = await request("/jobs", { origin: "http://localhost:3000" })
    assert.equal(
      res.headers.get("access-control-allow-origin"),
      "http://localhost:3000"
    )
  })

  // ---------------------------------------------------------------- rate limit
  await check("Write rate limit returns 429 after 60 requests", async () => {
    let saw429 = false

    for (let index = 0; index < 65; index += 1) {
      const res = await request("/jobs", {
        method: "POST",
        body: jobBody(),
      })

      if (res.status === 429) {
        saw429 = true
        break
      }
    }

    assert.equal(saw429, true)
  })
} catch (error) {
  console.error("Smoke test crashed:", error.message)
  process.exitCode = 1
} finally {
  if (serverProcess) {
    serverProcess.kill()
  }

  try {
    const db = client.db("hireloopdb")

    await db
      .collection("applications")
      .deleteMany({ _id: { $in: created.applicationIds } })
    await db.collection("jobs").deleteMany({ _id: { $in: created.jobIds } })
    await db
      .collection("session")
      .deleteMany({ token: { $in: created.sessionTokens } })
    await db.collection("user").deleteMany({ _id: { $in: created.userIds } })

    console.log("Cleaned up all temporary test records.")
  } catch (error) {
    console.error("Cleanup failed:", error.message)
  }

  await client.close()

  const passed = results.filter((result) => result.status === "PASS").length
  const failed = results.filter((result) => result.status === "FAIL").length
  console.log(`\nSummary: ${passed} passed, ${failed} failed, ${results.length} total`)

  if (failed > 0) process.exitCode = 1
}
