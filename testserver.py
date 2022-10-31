import pybox, os
from flask import Flask

app     = Flask(__name__)
sandbox = pybox.Sandbox()#Sandbox in which to run flask routes
sandbox.set_security_mode(pybox.Security.safe)
"""
safe_threaded should be used for this application, but it cant be used because eval is used in the eval_route function
so safe is used instead which could raise issues when another non-sandboxed function tries to access globals while
the sandboxed function is running
"""
SUPER_SECURE_PASSWORDS = {'admin': 'password'}


@app.route('/eval/<code>')
@sandbox.sandbox
def eval_route(code):
    return str(eval(code))

app.run(port=5001)