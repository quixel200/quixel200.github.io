+++
date = '2025-08-18T16:00:25+05:30'
draft = false
title = 'Web Security'
+++

# Path Traversal 

- The description is more than enough to solve these. This might seem very simple but it [happens more often than you think](https://hackernoon.com/a-deep-dive-into-path-traversal-vulnerabilities)
- **curl hates relative paths**, it will resolve paths automatically, read the man pages to know more.I would recommend using python for testing. 

# Command Injection 

- The only hint for level 6:
Think of *every* character you can use. Think about how you run multiple commands in your terminal or in a bash script

# SQL injection

- If you understand how SQL injection works, you'll breeze through these, if not, watch the lecture video again

# XSS

Before trying anything, cat the source code and understand what it's doing.
- Verify your payloads, especially if they're multi-stage. Use the inspect source to your advantage.

# CSRF 

Basic python flask server template, in case you're too lazy to copy paste from the source code

```
import flask
import os

app = flask.Flask(__name__)


@app.route("/", methods=["GET"])
def challenge():
    return "hello"


app.secret_key = os.urandom(8)
app.run("localhost", 1337)
```


