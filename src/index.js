const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const { authRoutes, userRoutes, reportsRoutes } = require("./routes");
const { authenticateReq, injectReqId } = require('./middlewares');

const app = express();
const port = process.env.PORT || 5000;

app.use(bodyParser.json());
app.use(cookieParser());
app.use(cors())

// Start the server
app.listen(port, () => {
 console.log(`Server listening on port ${port} at ${new Date().toString()}`);
});

// Request ID middleware
app.use(injectReqId);



app.use("/auth", authRoutes);
app.use("/users", authenticateReq, userRoutes);
app.use("/reports", authenticateReq, reportsRoutes);
