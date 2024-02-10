import { MongoClient, ObjectId, ServerApiVersion } from "mongodb";
import express from "express";
import cors from "cors";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";

const app = express();
app.use(express.json());
app.use(cors());
dotenv.config();

const uri = process.env.MONGODB_URI;

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

const authMiddleware = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) {
    return res.send({ error: true, message: "unauthorized access" });
  }
  const secret = process.env.JWT_SECRET_TOKEN;
  jwt.verify(token, secret);
  next();
};

async function run() {
  const db = client.db("book_db");
  const userCollection = db.collection("users");
  const booksCollection = db.collection("books");
  const reviewsCollection = db.collection("reviews");
  const statusCollection = db.collection("status");

  app.get("/", (_req, res) => {
    res.send("React ts server is running!");
  });

  app.post("/api/token", async (req, res) => {
    const data = req.body;
    const user = await userCollection.findOne({ email: data.email });
    if (!user) {
      return res.status(400).send("User does not exist");
    }
    const payload = {
      id: user._id,
      name: user.name,
      email: user.email,
    };
    const JWToken = process.env.JWT_SECRET_TOKEN;
    const token = jwt.sign(payload, JWToken);
    return res.send({ token });
  });

  app.post("/api/auth/signup", async (req, res) => {
    try {
      const data = req.body;
      const { name, email, password } = data;
      const existingUser = await userCollection.findOne({ email });
      if (existingUser) {
        return res.status(400).send("User already exists");
      }
      const hashedPassword = await bcrypt.hash(password, 10);
      const user = { name, email, password: hashedPassword };
      const createUser = await userCollection.insertOne(user);
      if (!createUser) {
        return res.status(400).send("User not created");
      }
      const payload = {
        name: user.name,
        email: user.email,
      };
      const JWTtoken = process.env.JWT_SECRET_TOKEN;
      const token = jwt.sign(payload, JWTtoken);
      return res.send({ token });
    } catch (error) {
      console.log(error.message);
    }
  });

  app.post("/api/auth/signin", async (req, res) => {
    try {
      const { email, password } = req.body;
      const user = await userCollection.findOne({ email });
      if (!user) {
        return res.status(400).send("User does not exist");
      }
      const isPasswordCorrect = await bcrypt.compare(password, user?.password);
      if (!isPasswordCorrect) {
        return res.status(400).send("Password is incorrect");
      }
      const payload = {
        name: user.name,
        email: user.email,
      };
      const JWTtoken = process.env.JWT_SECRET_TOKEN;
      const token = jwt.sign(payload, JWTtoken);
      return res.send({ token });
    } catch (error) {
      console.log(error.message);
    }
  });

  app.get("/api/users", authMiddleware, async (_req, res) => {
    try {
      const users = await userCollection.find().toArray();
      return res.send(users);
    } catch (error) {
      console.log(error.message);
    }
  });

  app.patch("/api/users/:id", authMiddleware, async (req, res) => {
    try {
      const { id } = req.params;
      const user = req.body;
      const result = await userCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: user }
      );
      return res.send(result);
    } catch (error) {
      console.log(error.message);
    }
  });

  app.delete("/api/users/:id", authMiddleware, async (req, res) => {
    try {
      const { id } = req.params;
      const result = await userCollection.deleteOne({
        _id: new ObjectId(id),
      });
      return res.send(result);
    } catch (error) {
      console.log(error.message);
    }
  });

  app.get("/api/books", async (req, res) => {
    try {
      const { search } = req.query;
      const query = search
        ? {
            $or: [
              { title: { $regex: search, $options: "i" } },
              { author: { $regex: search, $options: "i" } },
              { genre: { $regex: search, $options: "i" } },
            ],
          }
        : {};
      const books = await booksCollection
        .find(query)
        .sort({ createdAt: -1 })
        .toArray();
      return res.send(books);
    } catch (error) {
      console.log(error.message);
    }
  });

  app.get("/api/books/recent", async (req, res) => {
    try {
      const books = await booksCollection
        .find()
        .sort({ createdAt: -1 })
        .limit(10)
        .toArray();
      return res.send(books);
    } catch (error) {
      console.log(error.message);
    }
  });

  app.post("/api/books", authMiddleware, async (req, res) => {
    try {
      const token = req.headers.authorization?.split(" ")[1];
      const JWTtoken = process.env.JWT_SECRET_TOKEN;
      const decodedToken = jwt.verify(token, JWTtoken);
      const { email } = decodedToken;
      const book = req.body;
      book.email = email;
      book.createdAt = new Date();
      const result = await booksCollection.insertOne(book);
      return res.send(result);
    } catch (error) {
      console.log(error.message);
    }
  });

  app.get("/api/books/:id", async (req, res) => {
    try {
      const id = req.params.id;
      const book = await booksCollection.findOne({ _id: new ObjectId(id) });
      return res.send(book);
    } catch (error) {
      console.log(error.message);
    }
  });

  app.get("/api/books/user/:email", async (req, res) => {
    try {
      const email = req.params.email;
      const books = await booksCollection.find({ email }).toArray();
      return res.send(books);
    } catch (error) {
      console.log(error.message);
    }
  });

  app.patch("/api/books/:id", authMiddleware, async (req, res) => {
    try {
      const book = req.body;
      const { id } = req.params;
      const token = req.headers.authorization?.split(" ")[1];
      const JWTtoken = process.env.JWT_SECRET_TOKEN;
      const decodedToken = jwt.verify(token, JWTtoken);
      const { email } = decodedToken;
      const findBook = await booksCollection.findOne({
        _id: new ObjectId(id),
      });
      if (findBook?.email !== email) {
        return res.send("Unauthorized access");
      }
      const result = await booksCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: book }
      );
      return res.send(result);
    } catch (error) {
      console.log(error.message);
    }
  });

  app.delete("/api/books/:id", authMiddleware, async (req, res) => {
    try {
      const { id } = req.params;
      const token = req.headers.authorization?.split(" ")[1];
      const JWTtoken = process.env.JWT_SECRET_TOKEN;
      const decodedToken = jwt.verify(token, JWTtoken);
      const { email } = decodedToken;
      const findBook = await booksCollection.findOne({
        _id: new ObjectId(id),
      });
      if (findBook?.email !== email) {
        return res.send("Unauthorized access");
      }
      const result = await booksCollection.deleteOne({
        _id: new ObjectId(id),
      });
      return res.send(result);
    } catch (error) {
      console.error(error.message);
    }
  });

  app.get("/api/reviews/:bookId", async (req, res) => {
    const { bookId } = req.params;
    const result = await reviewsCollection.find({ bookId }).toArray();
    return res.send(result);
  });

  app.post("/api/reviews/:bookId", authMiddleware, async (req, res) => {
    const { bookId } = req.params;
    const token = req.headers.authorization?.split(" ")[1];
    const JWTtoken = process.env.JWT_SECRET_TOKEN;
    const decodedToken = jwt.verify(token, JWTtoken);
    const { name, email } = decodedToken;
    const data = req.body;
    data.bookId = bookId;
    data.name = name;
    data.email = email;
    const result = await reviewsCollection.insertOne(data);
    return res.send(result);
  });

  app.get("/api/status", async (req, res) => {
    const { status, user } = req.query;
    const query = status && user
      ? {
          $and: [
            { status: { $regex: status, $options: "i" } },
            { user: { $regex: user, $options: "i" } },
          ],
        }
      : {};
    const result = await statusCollection.find(query).toArray();
    return res.send(result);
  });

  app.post("/api/status", authMiddleware, async (req, res) => {
    const data = req.body;
    const token = req.headers.authorization?.split(" ")[1];
    const JWTtoken = process.env.JWT_SECRET_TOKEN;
    const decodedToken = jwt.verify(token, JWTtoken);
    const { email } = decodedToken;
    const user = await userCollection.findOne({ email });
    if (!user) {
      return res.send("User not found");
    }
    data.user = email;
    const result = await statusCollection.insertOne(data);
    return res.send(result);
  });

  app.patch("/api/status/:id", authMiddleware, async (req, res) => {
    const { id } = req.params;
    const status = req.body;
    const result = await statusCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: status }
    );
    return res.send(result);
  });

  app.delete("/api/status/:id", authMiddleware, async (req, res) => {
    try {
      const { id } = req.params;
      const result = await statusCollection.deleteOne({
        _id: new ObjectId(id),
      });
      return res.send(result);
    } catch (error) {
      console.log(error.message);
    }
  });
}

run().catch(console.dir);

const port = process.env.PORT || 5000;

app.listen(port, () => {
  console.log(`Backend app listening on port ${port}`);
});
