import { MongoClient, ObjectId, ServerApiVersion } from "mongodb";
import express, { Request, Response, NextFunction } from "express";
import cors from "cors";
import bcrypt from "bcrypt";
import jwt, { Secret } from "jsonwebtoken";
import dotenv from "dotenv";

const app = express();
app.use(express.json());
app.use(cors());
dotenv.config();

const uri = process.env.MONGODB_URI as string;

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

const authMiddleware = (req: Request, res: Response, next: NextFunction) => {
  const authorization = req.headers.authorization;
  if (!authorization) {
    return res.send({ error: true, message: "unauthorized access" });
  }
  const token = authorization.split(" ")[1];
  if (!token || token === "") {
    return res.send({ error: true, message: "unauthorized token" });
  }
  // const jwtToken = process.env.JWT_SECRET_TOKEN as string;
  // jwt.verify(token, jwtToken);
  next();
};

async function run() {
  try {
    await client.connect();
    await client.db("book_catalog").command({ ping: 1 });
    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!"
    );

    const database = client.db("book_catalog");
    const userCollection = database.collection("users");
    const booksCollection = database.collection("books");
    const reviewsCollection = database.collection("reviews");
    const statusCollection = database.collection("status");

    app.post("/jwt", async (req, res) => {
      const user = req.body;
      const JWToken = process.env.JWT_SECRET_TOKEN as Secret;
      const token = jwt.sign(user, JWToken);
      return res.send({ token });
    });

    app.post("/api/auth/sign-up", async (req: Request, res: Response) => {
      const data = req.body;
      const { name, email, password } = data;
      const existingUser = await userCollection.findOne({ email });
      if (existingUser) {
        return res.send("User already exists");
      }
      const hashedPassword = await bcrypt.hash(password, 10);
      const user = { name, email, password: hashedPassword };
      const result = await userCollection.insertOne(user);
      return res.send(result);
    });

    app.post("/api/auth/sign-in", async (req: Request, res: Response) => {
      const { email, password } = req.body;
      const user = await userCollection.findOne({ email });
      if (!user) {
        return res.send("User does not exist");
      }
      const isPasswordCorrect = await bcrypt.compare(password, user?.password);
      if (!isPasswordCorrect) {
        return res.send("Password is incorrect");
      }
      const payload = {
        user: user.name,
        email: user.email,
      };
      const JWTtoken = process.env.JWT_SECRET_TOKEN as Secret;
      const token = jwt.sign(payload, JWTtoken);
      return res.json(token);
    });

    app.get(
      "/api/users",
      authMiddleware,
      async (_req: Request, res: Response) => {
        const users = await userCollection.find({}).toArray();
        return res.send(users);
      }
    );

    app.get("/api/books", async (_req: Request, res: Response) => {
      const books = await booksCollection.find({}).toArray();
      return res.send(books);
    });

    app.post(
      "/api/books",
      authMiddleware,
      async (req: Request, res: Response) => {
        const token = req.headers.authorization?.split(" ")[1];
        const decodedToken = jwt.decode(token as string);
        const { user, email } = decodedToken as { user: string, email: string };
        const book = req.body;
        book.user = user;
        book.email = email;
        const result = await booksCollection.insertOne(book);
        return res.send(result);
      }
    );

    app.get("/api/books/:id", async (req: Request, res: Response) => {
      const id = req.params.id;
      const book = await booksCollection.findOne({ _id: new ObjectId(id) });
      return res.send(book);
    });

    app.patch(
      "/api/books/:id",
      authMiddleware,
      async (req: Request, res: Response) => {
        const book = req.body;
        const { id } = req.params;
        const token = req.headers.authorization?.split(" ")[ 1 ] as string;
        const decodedToken = jwt.decode(token);
        const { email } = decodedToken as { email: string };
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
      }
    );

    app.delete(
      "/api/books/:id",
      authMiddleware,
      async (req: Request, res: Response) => {
        try {
          const { id } = req.params;
        const token = req.headers.authorization?.split(" ")[ 1 ] as string;
        const decodedToken = jwt.decode(token);
        const { email } = decodedToken as { email: string };
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
        } catch (error: any) {
          console.error(error.message);
        }
      }
    );

    app.get("/api/reviews/:bookId", async (req: Request, res: Response) => {
      const { bookId } = req.params;
      const result = await reviewsCollection
        .find({ bookId })
        .toArray();
      return res.send(result);
    });

    app.post(
      "/api/reviews/:bookId",
      authMiddleware,
      async (req: Request, res: Response) => {
        const { bookId } = req.params;
        const token = req.headers.authorization?.split(" ")[1] as string;
        const decodedToken = jwt.decode(token);
        const { user, email } = decodedToken as { user: string; email: string };
        const data = req.body;
        data.bookId = bookId;
        data.user = user;
        data.email = email;
        const result = await reviewsCollection.insertOne(data);
        return res.send(result);
      }
    );

    app.get(
      "/api/status",
      authMiddleware,
      async (req: Request, res: Response) => {
        const token = req.headers.authorization?.split(" ")[1];
        const decodedToken = jwt.decode(token as string);
        const { email } = decodedToken as { email: string };
        const status = await statusCollection.find({ email }).toArray();
        return res.send(status);
      }
    );

    app.post(
      "/api/status",
      authMiddleware,
      async (req: Request, res: Response) => {
        const token = req.headers.authorization?.split(" ")[1] as string;
        const decodedToken = jwt.decode(token);
        const { user, email } = decodedToken as { user: string, email: string };
        const findUser = await userCollection.findOne({ email });
        if (!findUser) {
          return res.send("Unauthorized access");
        }
        const status = req.body;
        status.user = user;
        status.email = email;
        const result = await statusCollection.insertOne(status);
        return res.send(result);
      }
    );

    app.patch(
      "/api/status/:id",
      authMiddleware,
      async (req: Request, res: Response) => {
        const {id} = req.params;
        const status = req.body;
        const result = await statusCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: status }
        );
        return res.send(result);
      }
    );

    app.delete(
      "/api/status/:id",
      authMiddleware,
      async (req: Request, res: Response) => {
        const {id} = req.params;
        const result = await statusCollection.deleteOne({
          _id: new ObjectId(id),
        });
        return res.send(result);
      }
    );
  } catch (error) {
    console.log(error);
  }
}
run().catch(console.dir);

app.get("/", (_req, res) => {
  res.send("Hello World!");
});

const port = 5000;
app.listen(port, () => {
  console.log(`Backend app listening on port ${port}`);
});
