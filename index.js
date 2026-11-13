 import express from "express";
 import cors from "cors";
 import dotenv from "dotenv";
 import { MongoClient, ObjectId } from 'mongodb';

 dotenv.config();
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


 app.get('/', (req, res)=>{
    res.send("hireloop is looping")
 })


 app.listen(port, ()=>{
    console.log(`hireloop is running port ${port}`)
 })


 app.get('/users', async (req, res)=>{
  const cursor = users.find({});
  const result = await cursor.toArray();
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
  const userId = req.query.userId;

  const query = {userId: userId}
  const cursor = applications.find(query);
  const result = await cursor.toArray();
  res.send(result);
})