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
  const authorization = req.headers.authorization;
  if (!authorization) {
    return res.send({ error: true, message: "unauthorized access" });
  }
  const token = authorization.split(" ")[1];
  if (!token || token === "") {
    return res.send({ error: true, message: "unauthorized token" });
  }
  const jwtToken = process.env.JWT_SECRET_TOKEN;
  jwt.verify(token, jwtToken);
  next();
};

async function run() {
  try {

    const database = client.db("book_catalog");
    const userCollection = database.collection("users");
    const booksCollection = database.collection("books");
    const reviewsCollection = database.collection("reviews");
    const statusCollection = database.collection("status");

    app.post("/jwt", async (req, res) => {
      const user = req.body;
      const JWToken = process.env.JWT_SECRET_TOKEN;
      const token = jwt.sign(user, JWToken);
      return res.send({ token });
    });

    app.post("/api/auth/sign-up", async (req, res) => {
      try {
        const data = req.body;
        const { name, email, password } = data;
        const existingUser = await userCollection.findOne({ email });
        if (existingUser) {
          return res.send("User already exists");
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = { name, email, password: hashedPassword };
        const createUser = await userCollection.insertOne(user);
        if (!createUser) {
          return res.send("User not created");
        }
        const payload = {
          name: user.name,
          email: user.email,
        };
        const JWTtoken = process.env.JWT_SECRET_TOKEN;
        const token = jwt.sign(payload, JWTtoken);
        return res.send(token);
      } catch (error) {
        console.log(error.message);
      }
    });

    app.post("/api/auth/sign-in", async (req, res) => {
      try {
        const { email, password } = req.body;
        const user = await userCollection.findOne({ email });
        if (!user) {
          return res.send("User does not exist");
        }
        const isPasswordCorrect = await bcrypt.compare(
          password,
          user?.password
        );
        if (!isPasswordCorrect) {
          return res.send("Password is incorrect");
        }
        const payload = {
          name: user.name,
          email: user.email,
        };
        const JWTtoken = process.env.JWT_SECRET_TOKEN;
        const token = jwt.sign(payload, JWTtoken);
        return res.json(token);
      } catch (error) {
        console.log(error.message);
      }
    });

    app.get("/api/books", async (req, res) => {
      try {
        const search = req.query.search;
        const query = search
          ? {
              $or: [
                { title: { $regex: search, $options: "i" } },
                { author: { $regex: search, $options: "i" } },
                { genre: { $regex: search, $options: "i" } },
              ],
            }
          : {};
        const books = booksCollection.find(query)
        const result = await books.toArray();
        return res.send(result);
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
        console.log(error.message)
      }
    })

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

    app.get("/api/status/:email", async (req, res) => {
      const { email } = req.params;
      const status = await statusCollection.find({ email }).toArray();
      return res.send(status);
    });

    app.post("/api/status/:bookId", authMiddleware, async (req, res) => {
      const { bookId } = req.params;
      const token = req.headers.authorization?.split(" ")[1];
      const JWTtoken = process.env.JWT_SECRET_TOKEN;
      const decodedToken = jwt.verify(token, JWTtoken);
      const { email } = decodedToken;
      const findUser = await userCollection.findOne({ email });
      if (!findUser) {
        return res.send("User not found");
      }
      const status = req.body;
      delete status._id;
      status.bookId = bookId;
      const result = await statusCollection.insertOne(status);
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
      const { id } = req.params;
      const result = await statusCollection.deleteOne({
        _id: new ObjectId(id),
      });
      return res.send(result);
    });
    
    await client.connect();
    await client.db("book_catalog").command({ ping: 1 });
    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!"
    );

  } catch (error) {
    console.log(error);
  }
}

run();

app.get("/api", (_req, res) => {
  res.send("api is running successfully!");
});

app.get("/", (_req, res) => {
  res.send("React ts server is running!");
});

const port = process.env.PORT;
app.listen(port, () => {
  console.log(`Backend app listening on port ${port}`);
});
