import functools
import time
from dataclasses import dataclass
from functools import wraps


@dataclass
class InventryItems:
    name = str
    quantity: int = 0
    price = float

    def get_cost(self) -> float:
        self.quantity * self.price

    def __init__(self, name: str, price: float, quantity: int = 0):
        self.name = name
        self.quantity = quantity
        self.price = price


def slow_down(func):
    """slow down code"""

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        time.sleep(1)
        return func(*args, **kwargs)

    return wrapper


@slow_down
def count_down(number):
    if number < 1:
        print("done counting!!")
    else:
        print(number)
        count_down(number - 1)


# count_down(9)


def log_call(func):
    wraps(func)

    def wrapper(*args, **kwargs):
        print(f"[Log] Before function call of {func.__name__}")
        result = func(*args, **kwargs)
        print(f"[Log] after calling function: {func.__name__}")
        return result

    return wrapper

def require_role(role):
    def decorator(func):
        @wraps(func)
        def wrapper(user, *args, **kwargs):
            if user["role"] != role:
                raise Exception("Unauthorized")
            return func(user, *args, **kwargs)
        return wrapper
    return decorator



@log_call
def get_userId():
    return {"userId": 1}

# get_userId()


# from typing import NewType

# UserId = NewType("UserId", int)


# def get_user_id(userId: UserId) -> str:
#     print(userId)


# get_user_id(UserId(21))
# get_user_id(-1)

# def first_decorator(func1):
#     def inner():
#         print("first decorator!")
#         func1()

#     return inner


# def second_decorator(func):
#     def inner():
#         print("second decorator!")
#         func()

#     return inner


# @first_decorator
# @second_decorator
# def final_func():
#     print("final destination func!")


# # decoreded_fuc = first_decorator(second_decorator(final_func))
# # decoreded_fuc()


# def smart_divide(func):
#     def inner(a, b):
#         if b == 0:
#             print("You can not divide by 0")
#             return
#         return func(a, b)

#     return inner


# @smart_divide
# def divide(a, b):
#     print(a / b)


# # divide(2,5)

# divide(2,0)
