 import express from "express";
 import cors from "cors";
 import dotenv from "dotenv";
 import { MongoClient, ObjectId } from 'mongodb';
 import Stripe from "stripe";
dotenv.config();

 const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

 const app = express();
 const port = process.env.PORT || 5000;

 //mideleware
 app.use(express.json());
 app.use(cors());


const client = new MongoClient(process.env.MONGODB_URL);
export async function connectToMongoDB() {
  try {
    await client.connect();
    console.log("You successfully connected to MongoDB!");
    return client;
  } catch (err) {
    console.dir(err);
  }
}

// Call this only when your application terminates
export async function disconnectFromMongoDB() {
  await client.close();
}

const connectedClient = await connectToMongoDB();
const database = connectedClient.db("hireloopdb");
const users = database.collection("user");
const jobs = database.collection("jobs");
const applications = database.collection("applications");
const payments = database.collection("payments");


 app.get('/', (req, res)=>{
    res.send("hireloop is looping")
 })


 app.listen(port, ()=>{
    console.log(`hireloop is running port ${port}`)
 })

//users related apis
 app.get('/users', async (req, res)=>{
  const cursor = users.find({});
  const result = await cursor.toArray();
  res.send(result);
 })


 app.get("/users/:id/premium", async(req, res)=>{
  const id = req.params.id;
  const query = {_id: new ObjectId(id)};
  const result = await users.findOne(query, {projection: {premium: 1}});
  res.send(result);
 })


 //jobs related api
 //add-jobs
app.post('/jobs', async (req, res)=>{
  const job = req.body;
  const result = await jobs.insertOne(job);
  res.send(result)
})


app.get("/jobs", async(req, res)=>{

  const query = {};
  console.log("query", req.query)

  if(req.query){

    if(req.query.jobType){
      query.jobType = { $regex: `^${req.query.jobType}$`, $options: "i" };
    }
    if(req.query.isRemote){
      query.isRemote = req.query.isRemote === "true";
    }
    if(req.query.category){
      query.category = { $regex: `^${req.query.category}$`, $options: "i" };
    }
    if(req.query.recruiterId){
      query.category = req.query.category;
    }

    if (req.query.search) {
    query.$or = [
      { title: { $regex: req.query.search, $options: "i" } },
      { company: { $regex: req.query.search, $options: "i" } },
      { responsibilities: { $regex: req.query.search, $options: "i" } },
      { requirements: { $regex: req.query.search, $options: "i" } },
    ];
  }
   
  }
  const cursor = jobs.find(query);
  const result = await cursor.toArray();
  res.send(result)
})


app.delete("/jobs/:id",async (req, res)=>{
  const id = req.params.id;
  const query = {_id: new ObjectId(id)};
  const result = await jobs.deleteOne(query);
  res.send(result);
})



//jobs details 
//jobs count
app.get("/jobs/count", async (req, res) => {
  const query = {};
  if (req.query.recruiterId) {
    query.recruiterId = req.query.recruiterId;
  }
  const result = await jobs.countDocuments(query);
  res.send({ count: result });
});

app.get("/jobs/:id", async(req, res)=>{
  const id = req.params.id;
  const query = {_id: new ObjectId(id)};
  const result = await jobs.findOne(query);
  res.send(result);
})



//application realted apis
app.post("/applications", async(req, res)=>{
  const application = req.body;
  const result = await applications.insertOne(application);
  res.send(result)
})



app.get("/applications", async(req, res)=>{
  const query = {};
  if(req.query.applicantId){
    query.userId = req.query.applicantId;
  };

  if(req.query.jobId){
    query.jobId = req.query.jobId;
  };

  if(req.query.jobIds){
    const jobIds = String(req.query.jobIds).split(",").filter(Boolean);
    if(jobIds.length > 0){
      query.jobId = { $in: jobIds };
    }
  };

  const cursor = applications.find(query);
  const result = await cursor.toArray();
  res.send(result);
})



app.get("/applications/count", async(req, res)=>{
  const query = {};
  if(req.query.applicantId){
    query.userId = req.query.applicantId;
  }
  const result = await applications.countDocuments(query)
  res.send({count: result});
})



// The statuses an application is allowed to move through (keep in sync with
// APPLICATION_STATUSES in hireloop/lib/actions/applications.ts).
const APPLICATION_STATUSES = [
  "Applied",
  "Review",
  "Shortlisted",
  "Interview",
  "Offered",
  "Rejected",
];

//application status change
const updateApplicationStatusHandler = async (req, res) => {
  const { id } = req.params;
  const status = req.body?.status;

  // 1. Validate before touching MongoDB, so bad input is a 400 (not a 500).
  if (!ObjectId.isValid(id)) {
    return res.status(400).send({ message: "Invalid application id" });
  }

  if (!APPLICATION_STATUSES.includes(status)) {
    return res.status(400).send({
      message: `Status must be one of: ${APPLICATION_STATUSES.join(", ")}`,
    });
  }

  const query = { _id: new ObjectId(id) };
  const updateDoc = {
    $set: {
      status,
      updatedAt: new Date().toISOString(),
    },
  };

  try {
    const result = await applications.updateOne(query, updateDoc);

    // 2. Nothing matched = the application does not exist.
    if (result.matchedCount === 0) {
      return res.status(404).send({ message: "Application not found" });
    }

    res.send({ ...result, status });
  } catch (error) {
    console.error("Failed to update application status:", error);
    res.status(500).send({ message: "Failed to update application status" });
  }
};

// Plural path matches the other /applications routes; the singular one is kept
// so older clients (and manual Postman tests) keep working.
app.patch("/applications/:id", updateApplicationStatusHandler);
app.patch("/application/:id", updateApplicationStatusHandler);



//payments related apis
app.post('/payments/checkout-verify', async(req, res)=>{
  const {sessionId} = req.body;

  if(!sessionId){
    return res.send({success: false, message: "Session ID is required"});
  }

  const {
    status,
    payment_status,
    metadata,
    customer_email,
    payment_intent,} = await stripe.checkout.sessions.retrieve(sessionId)

    //1.is used new session
    //2.check is the session is for th ecurrently looged in user
    //3.insert collection into the payment collection
    //4.update user information as premium user

  if (status === "complete" && payment_status === "paid"){

    const sessionQuery = {sessionId};
    const existingPayment = await payments.findOne(sessionQuery);

    if(existingPayment){
      return res.send({success: false, message: 'Payment already verified'});
    }
    const payment = {
    status,
    sessionId,
    payment_status,
    customer_email,
    userId: metadata.userId,
    payment_intent,
    payment_date: new Date(),
    }

    const result = await payments.insertOne(payment);

    //update the user table
    const query = {_id: new ObjectId(metadata.userId)};

    const updatedDoc = {
      $set:{
        premium: true,
      }
    }
    const updateResult = await users.updateOne(
      query,
      updatedDoc
    );
    res.send({success: true, result, updateResult});
    return;
  }

  res.send({success: false, message: "payment verification failed"})
})