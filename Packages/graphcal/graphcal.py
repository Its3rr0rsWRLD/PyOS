import turtle

def point(x,y):
    obj.forward(x*extension)
    obj.left(90)
    obj.forward(y*extension)
    points.append(obj.pos())
    home(obj,1)


def home(obj,isPoint):
        obj.up()
        obj.home()
        obj.goto(ObjectOrigin)
        if not isPoint:
            obj.down()


def CreateBase():
    for length in range(11):
        obj.left(90)
        obj.forward(length*extension)
        obj.stamp()
        obj.write(str(length))
        home(obj,False)
        obj.forward(length*extension)
        obj.stamp()
        obj.write(str(length))
        home(obj,False)


ObjectOrigin = (-100,-100)


points = []

extension = 40







fx =  input("Function: ")


window = turtle.Screen()
window.screensize(1000,1000)


draw = turtle.Turtle()
home(draw,0)
draw.hideturtle()
draw.speed(0)

obj = turtle.Turtle()
home(obj,0)
obj.speed(0)

CreateBase()

obj.up()
draw.up()

for x in range(-5,10):
    y = eval(fx)
    point(x,y)
    draw.goto(points[x+5])
    draw.down()

window.exitonclick()
