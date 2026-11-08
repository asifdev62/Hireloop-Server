 import express from "express";
 import cors from "cors";
 import dotenv from "dotenv";
 import { MongoClient } from 'mongodb';

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
const database = connectedClient.db("hireloopdb")
const users = database.collection("user")
const jobs = database.collection("jobs")


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
app.post('/add-jobs', async (req, res)=>{
  const job = req.body;
  const result = await jobs.insertOne(job);
  res.send(result)
})
