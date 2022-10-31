import inspect

class Security(object):
    """
    Notes on security:
     - To actually make it safe from most simple-moderate attacks, you need to do one of the following combinations:
        1. Disable imports and eval/exec
        2. Use unload_globals_while_running
        3. Enable all expiremental features is the most safe
    
    Here are demos on how to exploit the other feature combinations:
        - Imports disabled but eval/exec enabled:
            - exec('import os', globals())
            - os.system('start cmd.exe /k echo pwned')
        - Imports enabled but unload_globals_while_running disabled:
            - import inspect
            - globals_ref = inspect.currentframe().f_back.f_globals
    """
    default:       str = 'default'#Disable nothing
    safe:          str = 'safe'#Disable everything import/eval/exec
    safe_threaded: str = 'safe_threaded'#Disable imports and eval/exec
    unsafe:        str = 'unsafe'#Disable nothing

class Sandbox(object):
    def __init__(self):
        self.enviorment = {}
        self.unload_globals_while_running = False
        self.block_imports                = False
        self.block_eval_and_exec          = False

        self.security_mode = 'default'
    
    def set_security_mode(self, mode: str):
        """
        Quick way to switch feature/security presets
        """
        if mode == Security.default or Security.unsafe:
            self.unload_globals_while_running = False
            self.block_imports                = False
            self.block_eval_and_exec          = False
        elif mode == Security.safe:
            self.unload_globals_while_running = True
            self.block_imports                = True
            self.block_eval_and_exec          = True
        elif mode == Security.safe_threaded:
            self.unload_globals_while_running = False
            self.block_imports                = True
            self.block_eval_and_exec          = True
        else:
            raise ValueError('Invalid security mode')
        self.security_mode = mode

    def strip_decorators(self, code: str):
        code = code.splitlines()
        for i in range(len(code)):
            if code[i].strip().startswith('@'):
                code[i] = ''
        return '\n'.join(code)
    
    def disguise_caller(self, func: callable):
        def wrapper(*args, **kwargs):
            return func(*args, **kwargs)
        return wrapper
    
    def block_inspect(self, func: callable):
        # modify the current frame
        frame = inspect.currentframe()
        frame.f_globals['TRY_AND_GET_ME'] = None
    
    def unload_globals(self) -> dict:
        globals_copy = globals().copy()
        globals().clear()
        return globals_copy
    
    def load_globals(self, globals_copy: dict):
        globals().update(globals_copy)
    
    def block(self, *args, **kwargs): #Accept any args/kwargs to prevent errors
        print("[Sandbox::WARN] Function blocked!")

    def sandbox(self, func):
        def wrapper(*args, **kwargs):
            #Get the function and semi-rewrite it to work in the sandbox
            code = inspect.getsource(func)
            code = self.strip_decorators(code)

            #Block imports if enabled
            if self.block_imports:
                lines = code.splitlines()
                for i in range(len(lines)):
                    if lines[i].strip().startswith('import'):
                        lines[i] = '    print("[Sandbox::WARN] Import blocked!")'
                code = '\n'.join(lines)

            #Get the resulting function  
            exec(code, self.enviorment, self.enviorment)
            del self.enviorment['__builtins__']
            result_name = list(self.enviorment.keys())[0]
            result = self.enviorment[result_name]

            #Unload the globals if the feature is enabled
            if self.unload_globals_while_running:
                locals()['globals_copy'] = self.unload_globals()
            if self.block_eval_and_exec:
                self.enviorment['eval'] = self.block
                self.enviorment['exec'] = self.block

            #Run the function
            try:
                resp = self.disguise_caller(result)(*args, **kwargs)

                #Reload the globals if the feature is enabled
                if self.unload_globals_while_running:
                    self.load_globals(locals()['globals_copy'])
            except Exception as e:
                if self.unload_globals_while_running:
                    self.load_globals(locals()['globals_copy'])
                raise e
            return resp
        return wrapper