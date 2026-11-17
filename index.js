import express from "express"
import cors from "cors"
import helmet from "helmet"
import rateLimit from "express-rate-limit"
import dotenv from "dotenv"
import { MongoClient, ObjectId } from "mongodb"
import Stripe from "stripe"
import { z, ZodError } from "zod"

dotenv.config()

/* -------------------------------------------------------------------------- */
/* Configuration                                                              */
/* -------------------------------------------------------------------------- */

const port = Number(process.env.PORT || 5000)

const MONGODB_URL = process.env.MONGODB_URL
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY

// Only these browser origins may call this API. Comma separated in .env.
const ALLOWED_ORIGINS = (
  process.env.FRONTEND_ORIGINS || "http://localhost:3000"
)
  .split(",")
  .map((origin) => origin.trim())
  .filter(Boolean)

if (!MONGODB_URL) {
  console.error("Missing MONGODB_URL. Refusing to start.")
  process.exit(1)
}

const stripe = STRIPE_SECRET_KEY ? new Stripe(STRIPE_SECRET_KEY) : null

const app = express()

// Set this to 1 only when the app runs behind a trusted reverse proxy.
if (process.env.TRUST_PROXY === "1") {
  app.set("trust proxy", 1)
}

/* -------------------------------------------------------------------------- */
/* Security middleware                                                        */
/* -------------------------------------------------------------------------- */

app.disable("x-powered-by")

app.use(
  helmet({
    // This service only returns JSON, so a page CSP is not useful here.
    contentSecurityPolicy: false,
    crossOriginResourcePolicy: { policy: "cross-origin" },
  })
)

app.use(
  cors({
    origin(origin, callback) {
      // No Origin header means a server-to-server call (for example Next.js
      // server actions). Those are not subject to browser CORS.
      if (!origin) return callback(null, true)
      if (ALLOWED_ORIGINS.includes(origin)) return callback(null, true)
      return callback(null, false)
    },
    credentials: true,
    methods: ["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    maxAge: 600,
  })
)

app.use(express.json({ limit: "100kb", strict: true }))

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 300,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { message: "Too many requests. Please try again later." },
})

const writeLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 60,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { message: "Too many requests. Please try again later." },
})

app.use(apiLimiter)

/* -------------------------------------------------------------------------- */
/* Database                                                                   */
/* -------------------------------------------------------------------------- */

const client = new MongoClient(MONGODB_URL, { serverSelectionTimeoutMS: 10_000 })

try {
  await client.connect()
  console.log("Connected to MongoDB")
} catch {
  // Never print the connection string or the driver error details.
  console.error("Could not connect to MongoDB. Refusing to start.")
  process.exit(1)
}

const database = client.db("hireloopdb")
const users = database.collection("user")
const sessions = database.collection("session")
const jobs = database.collection("jobs")
const applications = database.collection("applications")
const payments = database.collection("payments")

// Prevent duplicate applications even if two requests race each other.
// Best effort: existing duplicate rows make this fail, which is only logged.
try {
  await applications.createIndex(
    { userId: 1, jobId: 1 },
    { unique: true, name: "unique_application_per_user_job" }
  )
} catch {
  console.warn(
    "Could not create the unique application index (duplicate rows may exist)."
  )
}

/* -------------------------------------------------------------------------- */
/* Small helpers                                                              */
/* -------------------------------------------------------------------------- */

const ROLES = ["seeker", "recruiter", "admin"]
const APPLICATION_STATUSES = [
  "Applied",
  "Review",
  "Shortlisted",
  "Interview",
  "Offered",
  "Rejected",
]

const FREE_JOB_LIMIT = 2
const FREE_APPLICATION_LIMIT = 2

function normalizeRole(value) {
  const role = String(value ?? "")
    .split(",")[0]
    .trim()

  return ROLES.includes(role) ? role : "seeker"
}

function toObjectId(value) {
  if (typeof value !== "string" || !ObjectId.isValid(value)) return null
  return new ObjectId(value)
}

function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
}

function readTrimmedString(value, maxLength) {
  if (typeof value !== "string") return null
  const trimmed = value.trim()
  if (!trimmed || trimmed.length > maxLength) return null
  return trimmed
}

function httpError(status, message) {
  const error = new Error(message)
  error.status = status
  return error
}

/** Wraps an async route so rejected promises reach the error handler. */
function asyncHandler(handler) {
  return (req, res, next) => {
    Promise.resolve(handler(req, res, next)).catch(next)
  }
}

/** The only user fields that are ever sent to a client. */
function publicUser(user) {
  return {
    id: user._id.toString(),
    name: typeof user.name === "string" ? user.name : "",
    email: typeof user.email === "string" ? user.email : "",
    role: normalizeRole(user.role),
    premium: user.premium === true,
  }
}

/* -------------------------------------------------------------------------- */
/* Authentication (Better Auth session verification)                          */
/* -------------------------------------------------------------------------- */

function readSessionToken(req) {
  const header = req.headers.authorization

  if (typeof header === "string" && header.startsWith("Bearer ")) {
    const token = header.slice(7).trim()
    if (token.length >= 16 && token.length <= 512) return token
  }

  // Fallback for same-site browser calls. The signed cookie looks like
  // "<token>.<signature>"; the token itself is what is stored in MongoDB.
  const cookieHeader = req.headers.cookie
  if (typeof cookieHeader === "string") {
    for (const part of cookieHeader.split(";")) {
      const [rawName, ...rawValue] = part.trim().split("=")
      if (
        rawName === "better-auth.session_token" ||
        rawName === "__Secure-better-auth.session_token"
      ) {
        const value = decodeURIComponent(rawValue.join("="))
        const token = value.split(".")[0]
        if (token && token.length >= 16) return token
      }
    }
  }

  return null
}

/**
 * Resolves the signed-in user from the Better Auth session collection.
 * This is the same check Better Auth itself performs: the token must exist,
 * must not be expired, and must point at a real user.
 */
async function authenticate(req) {
  const token = readSessionToken(req)
  if (!token) return null

  const session = await sessions.findOne({ token })
  if (!session) return null

  const expiresAt =
    session.expiresAt instanceof Date
      ? session.expiresAt
      : new Date(session.expiresAt)

  if (!Number.isFinite(expiresAt.getTime()) || expiresAt <= new Date()) {
    return null
  }

  const userId =
    session.userId instanceof ObjectId
      ? session.userId
      : toObjectId(String(session.userId ?? ""))

  if (!userId) return null

  const user = await users.findOne({ _id: userId })
  if (!user) return null

  return { user, session }
}

const requireAuth = asyncHandler(async (req, res, next) => {
  const result = await authenticate(req)

  if (!result) {
    return res.status(401).json({ message: "Authentication required" })
  }

  req.auth = {
    user: publicUser(result.user),
    rawUser: result.user,
    session: result.session,
  }

  next()
})

function requireRole(...allowedRoles) {
  return (req, res, next) => {
    if (!req.auth) {
      return res.status(401).json({ message: "Authentication required" })
    }

    if (!allowedRoles.includes(req.auth.user.role)) {
      return res.status(403).json({ message: "You are not allowed to do this" })
    }

    next()
  }
}

/* -------------------------------------------------------------------------- */
/* Validation schemas                                                         */
/* -------------------------------------------------------------------------- */

const jobCreateSchema = z
  .object({
    title: z.string().trim().min(3).max(200),
    companyName: z.string().trim().min(1).max(200),
    category: z.string().trim().min(1).max(100),
    location: z.string().trim().min(1).max(200),
    deadline: z
      .string()
      .trim()
      .refine((value) => !Number.isNaN(new Date(value).getTime()), {
        message: "Deadline must be a valid date",
      }),
    minSalary: z.coerce.number().finite().min(0).max(1_000_000_000),
    maxSalary: z.coerce.number().finite().min(0).max(1_000_000_000),
    salaryFrequency: z.enum(["per hour", "per day", "per month", "per year"]),
    responsibilities: z.string().trim().max(5000).default(""),
    qualifications: z.string().trim().max(5000).default(""),
    jobType: z.enum(["Full-time", "Part-time", "Contract", "Internship"]),
    isRemote: z.boolean(),
  })
  // Reject extra fields such as recruiterId, recruiterEmail or _id.
  .strict()
  .refine((data) => data.maxSalary >= data.minSalary, {
    message: "Maximum salary must be greater than or equal to minimum salary",
    path: ["maxSalary"],
  })

const applicationCreateSchema = z
  .object({
    jobId: z.string().refine((value) => ObjectId.isValid(value), {
      message: "Invalid job id",
    }),
    resumeUrl: z.string().url().max(2048).optional(),
    coverLetter: z.string().trim().max(5000).optional(),
    portfolioUrl: z.string().url().max(2048).optional(),
  })
  .strict()

const applicationStatusSchema = z
  .object({
    status: z.enum(APPLICATION_STATUSES),
  })
  .strict()

const roleUpdateSchema = z
  .object({
    role: z.enum(ROLES),
  })
  .strict()

const checkoutVerifySchema = z
  .object({
    sessionId: z.string().trim().min(10).max(200),
  })
  .strict()

/* -------------------------------------------------------------------------- */
/* Public routes                                                              */
/* -------------------------------------------------------------------------- */

app.get("/", (req, res) => {
  res.json({ status: "ok", service: "hireloop-api" })
})

/**
 * Public job search. Only non-sensitive job fields are returned.
 * Query values are escaped before they reach MongoDB, which blocks regex
 * injection and very expensive patterns.
 */
app.get(
  "/jobs",
  asyncHandler(async (req, res) => {
    const query = {}

    const jobType = readTrimmedString(req.query.jobType, 40)
    if (jobType) {
      query.jobType = { $regex: `^${escapeRegex(jobType)}$`, $options: "i" }
    }

    const category = readTrimmedString(req.query.category, 100)
    if (category) {
      query.category = { $regex: `^${escapeRegex(category)}$`, $options: "i" }
    }

    if (typeof req.query.isRemote === "string") {
      if (req.query.isRemote === "true") query.isRemote = true
      if (req.query.isRemote === "false") query.isRemote = false
    }

    const recruiterId = readTrimmedString(req.query.recruiterId, 64)
    if (recruiterId) {
      if (!ObjectId.isValid(recruiterId)) {
        return res.status(400).json({ message: "Invalid recruiter id" })
      }
      query.recruiterId = recruiterId
    }

    const search = readTrimmedString(req.query.search, 100)
    if (search) {
      const safeSearch = escapeRegex(search)
      query.$or = [
        { title: { $regex: safeSearch, $options: "i" } },
        { companyName: { $regex: safeSearch, $options: "i" } },
        { responsibilities: { $regex: safeSearch, $options: "i" } },
        { qualifications: { $regex: safeSearch, $options: "i" } },
      ]
    }

    const result = await jobs
      .find(query, {
        projection: {
          title: 1,
          companyName: 1,
          category: 1,
          department: 1,
          location: 1,
          deadline: 1,
          minSalary: 1,
          maxSalary: 1,
          salaryFrequency: 1,
          responsibilities: 1,
          qualifications: 1,
          jobType: 1,
          isRemote: 1,
          recruiterId: 1,
          createdAt: 1,
        },
      })
      .sort({ createdAt: -1 })
      .limit(200)
      .toArray()

    res.json(result)
  })
)

// Must be declared before "/jobs/:id", otherwise Express treats "count" as an id.
app.get(
  "/jobs/count",
  requireAuth,
  requireRole("recruiter", "admin"),
  asyncHandler(async (req, res) => {
    const query = {}

    if (req.auth.user.role === "admin") {
      const recruiterId = readTrimmedString(req.query.recruiterId, 64)
      if (recruiterId) {
        if (!ObjectId.isValid(recruiterId)) {
          return res.status(400).json({ message: "Invalid recruiter id" })
        }
        query.recruiterId = recruiterId
      }
    } else {
      // Recruiters can only count their own jobs.
      query.recruiterId = req.auth.user.id
    }

    const result = await jobs.countDocuments(query)
    res.json({ count: result })
  })
)

app.get(
  "/jobs/:id",
  asyncHandler(async (req, res) => {
    const id = toObjectId(req.params.id)
    if (!id) return res.status(400).json({ message: "Invalid job id" })

    const result = await jobs.findOne(
      { _id: id },
      {
        projection: {
          title: 1,
          companyName: 1,
          category: 1,
          department: 1,
          location: 1,
          deadline: 1,
          minSalary: 1,
          maxSalary: 1,
          salaryFrequency: 1,
          responsibilities: 1,
          qualifications: 1,
          jobType: 1,
          isRemote: 1,
          recruiterId: 1,
          createdAt: 1,
        },
      }
    )

    if (!result) return res.status(404).json({ message: "Job not found" })

    res.json(result)
  })
)

/* -------------------------------------------------------------------------- */
/* Users                                                                      */
/* -------------------------------------------------------------------------- */

app.get(
  "/users",
  requireAuth,
  requireRole("admin"),
  asyncHandler(async (req, res) => {
    const result = await users
      .find(
        {},
        {
          projection: {
            name: 1,
            email: 1,
            role: 1,
            premium: 1,
            emailVerified: 1,
            banned: 1,
            createdAt: 1,
          },
        }
      )
      .sort({ createdAt: -1 })
      .limit(500)
      .toArray()

    res.json(
      result.map((user) => ({
        ...user,
        id: user._id.toString(),
        role: normalizeRole(user.role),
      }))
    )
  })
)

app.get(
  "/users/:id/premium",
  requireAuth,
  asyncHandler(async (req, res) => {
    const id = toObjectId(req.params.id)
    if (!id) return res.status(400).json({ message: "Invalid user id" })

    if (req.auth.user.role !== "admin" && req.auth.user.id !== id.toString()) {
      return res.status(403).json({ message: "You are not allowed to do this" })
    }

    const result = await users.findOne({ _id: id }, { projection: { premium: 1 } })

    if (!result) return res.status(404).json({ message: "User not found" })

    res.json({ premium: result.premium === true })
  })
)

app.patch(
  "/users/:id/role",
  requireAuth,
  requireRole("admin"),
  asyncHandler(async (req, res) => {
    const id = toObjectId(req.params.id)
    if (!id) return res.status(400).json({ message: "Invalid user id" })

    const { role } = roleUpdateSchema.parse(req.body)

    // An admin must not be able to remove their own last admin access by
    // accident. Another admin can still change it.
    if (id.toString() === req.auth.user.id && role !== "admin") {
      return res
        .status(400)
        .json({ message: "You cannot remove your own admin role" })
    }

    const result = await users.updateOne({ _id: id }, { $set: { role } })

    if (result.matchedCount === 0) {
      return res.status(404).json({ message: "User not found" })
    }

    res.json({
      acknowledged: result.acknowledged,
      matchedCount: result.matchedCount,
      modifiedCount: result.modifiedCount,
    })
  })
)

/* -------------------------------------------------------------------------- */
/* Jobs (recruiter only writes, ownership enforced)                           */
/* -------------------------------------------------------------------------- */

app.post(
  "/jobs",
  writeLimiter,
  requireAuth,
  requireRole("recruiter"),
  asyncHandler(async (req, res) => {
    const data = jobCreateSchema.parse(req.body)

    // Free recruiters can post a limited number of jobs. This limit is
    // enforced here, not in the browser.
    if (!req.auth.user.premium) {
      const existing = await jobs.countDocuments({
        recruiterId: req.auth.user.id,
      })

      if (existing >= FREE_JOB_LIMIT) {
        return res.status(403).json({
          message: "Free accounts can post up to 2 jobs. Upgrade to add more.",
        })
      }
    }

    const job = {
      ...data,
      // Identity always comes from the verified session.
      recruiterId: req.auth.user.id,
      recruiterEmail: req.auth.user.email,
      createdAt: new Date().toISOString(),
    }

    const result = await jobs.insertOne(job)

    res.status(201).json({
      acknowledged: result.acknowledged,
      insertedId: result.insertedId.toString(),
    })
  })
)

app.delete(
  "/jobs/:id",
  writeLimiter,
  requireAuth,
  requireRole("recruiter", "admin"),
  asyncHandler(async (req, res) => {
    const id = toObjectId(req.params.id)
    if (!id) return res.status(400).json({ message: "Invalid job id" })

    // A recruiter's ownership is part of the query, so another recruiter's
    // job simply does not match.
    const query =
      req.auth.user.role === "admin"
        ? { _id: id }
        : { _id: id, recruiterId: req.auth.user.id }

    const result = await jobs.deleteOne(query)

    if (result.deletedCount === 0) {
      return res.status(404).json({ message: "Job not found" })
    }

    res.json({
      acknowledged: result.acknowledged,
      deletedCount: result.deletedCount,
    })
  })
)

/* -------------------------------------------------------------------------- */
/* Applications                                                               */
/* -------------------------------------------------------------------------- */

app.post(
  "/applications",
  writeLimiter,
  requireAuth,
  requireRole("seeker"),
  asyncHandler(async (req, res) => {
    const data = applicationCreateSchema.parse(req.body)

    const job = await jobs.findOne({ _id: new ObjectId(data.jobId) })
    if (!job) return res.status(404).json({ message: "Job not found" })

    // A recruiter cannot apply to their own job posting.
    if (job.recruiterId === req.auth.user.id) {
      return res
        .status(403)
        .json({ message: "You cannot apply to your own job" })
    }

    // Free seekers can send a limited number of applications.
    if (!req.auth.user.premium) {
      const count = await applications.countDocuments({
        userId: req.auth.user.id,
      })

      if (count >= FREE_APPLICATION_LIMIT) {
        return res.status(403).json({
          message:
            "Free accounts can send up to 2 applications. Upgrade to apply for more.",
        })
      }
    }

    const alreadyApplied = await applications.findOne({
      userId: req.auth.user.id,
      jobId: data.jobId,
    })

    if (alreadyApplied) {
      return res
        .status(409)
        .json({ message: "You have already applied to this job" })
    }

    const application = {
      // Identity always comes from the verified session.
      userId: req.auth.user.id,
      applicantName: req.auth.user.name,
      applicantEmail: req.auth.user.email,
      // The job snapshot comes from the database, not from the request body.
      jobId: data.jobId,
      jobTitle: job.title,
      companyName: job.companyName,
      jobType: job.jobType,
      location: job.location,
      isRemote: job.isRemote === true,
      resumeUrl: data.resumeUrl,
      coverLetter: data.coverLetter,
      portfolioUrl: data.portfolioUrl,
      status: "Applied",
      appliedAt: new Date().toISOString(),
      archived: false,
    }

    try {
      const result = await applications.insertOne(application)

      res.status(201).json({
        acknowledged: result.acknowledged,
        insertedId: result.insertedId.toString(),
      })
    } catch (error) {
      if (error?.code === 11000) {
        return res
          .status(409)
          .json({ message: "You have already applied to this job" })
      }
      throw error
    }
  })
)

/** Job ids owned by the signed-in recruiter. */
async function getOwnedJobIds(recruiterId) {
  const ownedJobs = await jobs
    .find({ recruiterId }, { projection: { _id: 1 } })
    .toArray()

  return ownedJobs.map((job) => job._id.toString())
}

app.get(
  "/applications/count",
  requireAuth,
  asyncHandler(async (req, res) => {
    const query = {}

    if (req.auth.user.role === "admin") {
      // Admin can count everything, or filter by one applicant.
      const applicantId = readTrimmedString(req.query.applicantId, 64)
      if (applicantId) {
        if (!ObjectId.isValid(applicantId)) {
          return res.status(400).json({ message: "Invalid applicant id" })
        }
        query.userId = applicantId
      }
    } else if (req.auth.user.role === "recruiter") {
      query.jobId = { $in: await getOwnedJobIds(req.auth.user.id) }
    } else {
      // Seekers only ever see their own count.
      query.userId = req.auth.user.id
    }

    const result = await applications.countDocuments(query)
    res.json({ count: result })
  })
)

app.get(
  "/applications",
  requireAuth,
  asyncHandler(async (req, res) => {
    const query = {}

    if (req.auth.user.role === "admin") {
      const applicantId = readTrimmedString(req.query.applicantId, 64)
      if (applicantId) {
        if (!ObjectId.isValid(applicantId)) {
          return res.status(400).json({ message: "Invalid applicant id" })
        }
        query.userId = applicantId
      }

      const jobId = readTrimmedString(req.query.jobId, 64)
      if (jobId) {
        if (!ObjectId.isValid(jobId)) {
          return res.status(400).json({ message: "Invalid job id" })
        }
        query.jobId = jobId
      }
    } else if (req.auth.user.role === "recruiter") {
      // The recruiter scope always wins. Any client-supplied applicantId or
      // jobIds can only narrow the result, never widen it.
      const ownedJobIds = await getOwnedJobIds(req.auth.user.id)

      const requestedJobIds =
        typeof req.query.jobIds === "string"
          ? req.query.jobIds.split(",").map((value) => value.trim())
          : []

      const allowedJobIds = requestedJobIds.length
        ? ownedJobIds.filter((id) => requestedJobIds.includes(id))
        : ownedJobIds

      const jobId = readTrimmedString(req.query.jobId, 64)
      if (jobId) {
        if (!ObjectId.isValid(jobId)) {
          return res.status(400).json({ message: "Invalid job id" })
        }
        if (!ownedJobIds.includes(jobId)) {
          return res.status(404).json({ message: "Job not found" })
        }
        query.jobId = jobId
      } else {
        query.jobId = { $in: allowedJobIds }
      }
    } else {
      // Seekers can only read their own applications, even if they send
      // someone else's applicantId.
      query.userId = req.auth.user.id
    }

    const result = await applications
      .find(query)
      .sort({ appliedAt: -1 })
      .limit(500)
      .toArray()

    res.json(result)
  })
)

const updateApplicationStatusHandler = asyncHandler(async (req, res) => {
  const id = toObjectId(req.params.id)
  if (!id) return res.status(400).json({ message: "Invalid application id" })

  const { status } = applicationStatusSchema.parse(req.body)

  const application = await applications.findOne({ _id: id })
  if (!application) {
    return res.status(404).json({ message: "Application not found" })
  }

  if (req.auth.user.role !== "admin") {
    // Only the recruiter who owns the job may move its applications.
    const jobId = toObjectId(String(application.jobId ?? ""))
    if (!jobId) {
      return res.status(404).json({ message: "Application not found" })
    }

    const ownsJob = await jobs.findOne({
      _id: jobId,
      recruiterId: req.auth.user.id,
    })

    if (!ownsJob) {
      return res.status(404).json({ message: "Application not found" })
    }
  }

  const result = await applications.updateOne(
    { _id: id },
    { $set: { status, updatedAt: new Date().toISOString() } }
  )

  res.json({
    acknowledged: result.acknowledged,
    matchedCount: result.matchedCount,
    modifiedCount: result.modifiedCount,
    status,
  })
})

// Recruiters and admins only. A seeker can never change their own status.
app.patch(
  "/applications/:id",
  writeLimiter,
  requireAuth,
  requireRole("recruiter", "admin"),
  updateApplicationStatusHandler
)
// Older clients use the singular path.
app.patch(
  "/application/:id",
  writeLimiter,
  requireAuth,
  requireRole("recruiter", "admin"),
  updateApplicationStatusHandler
)

/* -------------------------------------------------------------------------- */
/* Payments                                                                   */
/* -------------------------------------------------------------------------- */

app.post(
  "/payments/checkout-verify",
  writeLimiter,
  requireAuth,
  asyncHandler(async (req, res) => {
    if (!stripe) {
      return res
        .status(503)
        .json({ success: false, message: "Payments are not configured" })
    }

    const { sessionId } = checkoutVerifySchema.parse(req.body)

    const session = await stripe.checkout.sessions.retrieve(sessionId)

    if (
      session.status !== "complete" ||
      session.payment_status !== "paid"
    ) {
      return res
        .status(400)
        .json({ success: false, message: "Payment verification failed" })
    }

    // The checkout session must belong to the signed-in user. Without this
    // check, someone could verify another user's session.
    if (session.metadata?.userId !== req.auth.user.id) {
      return res
        .status(403)
        .json({ success: false, message: "This payment is not yours" })
    }

    const existingPayment = await payments.findOne({ sessionId })
    if (existingPayment) {
      return res.json({ success: true, alreadyVerified: true })
    }

    const payment = {
      status: session.status,
      sessionId,
      payment_status: session.payment_status,
      customer_email: session.customer_details?.email ?? null,
      userId: req.auth.user.id,
      payment_intent: session.payment_intent,
      payment_date: new Date(),
    }

    const result = await payments.insertOne(payment)

    const updateResult = await users.updateOne(
      { _id: new ObjectId(req.auth.user.id) },
      { $set: { premium: true } }
    )

    res.json({
      success: true,
      result: {
        acknowledged: result.acknowledged,
        insertedId: result.insertedId.toString(),
      },
      updateResult: {
        acknowledged: updateResult.acknowledged,
        matchedCount: updateResult.matchedCount,
        modifiedCount: updateResult.modifiedCount,
      },
    })
  })
)

/* -------------------------------------------------------------------------- */
/* 404 + safe error handler                                                   */
/* -------------------------------------------------------------------------- */

app.use((req, res) => {
  res.status(404).json({ message: "Not found" })
})

app.use((error, req, res, next) => {
  if (res.headersSent) return next(error)

  if (error instanceof ZodError) {
    return res.status(400).json({
      message: "Invalid request data",
      errors: error.issues.map((issue) => ({
        field: issue.path.join(".") || "body",
        message: issue.message,
      })),
    })
  }

  if (error?.type === "entity.too.large") {
    return res.status(413).json({ message: "Request body is too large" })
  }

  const status =
    Number.isInteger(error?.status) && error.status >= 400 && error.status < 600
      ? error.status
      : 500

  // Log the message only. Never log request bodies, tokens or stack traces.
  if (status >= 500) {
    console.error("Unhandled API error:", error?.message ?? "Unknown error")
  }

  res.status(status).json({
    message: status >= 500 ? "Internal server error" : error.message,
  })
})

/* -------------------------------------------------------------------------- */
/* Startup                                                                    */
/* -------------------------------------------------------------------------- */

const server = app.listen(port, () => {
  console.log(`hireloop API listening on port ${port}`)
})

async function shutdown() {
  server.close(async () => {
    await client.close()
    process.exit(0)
  })
}

process.on("SIGINT", shutdown)
process.on("SIGTERM", shutdown)
