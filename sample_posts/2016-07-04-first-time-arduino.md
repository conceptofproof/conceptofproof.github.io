---
layout: post
title: Initiating Arduino
subtitle: Introduction to basic level Arduino programming
published: true
---

I remember the excitement when learning how logic gates and flip flops work in school, it's been a while since then so decided to try re-kindle the magic by learning how to program Arduino. I originally chose the Raspberry Pi to learn but it only became a proxy for our media hub, therefore I'm deciding to go down the microelectronics route and adopt an unsuspecting [Arduino Uno](https://www.arduino.cc/en/Main/ArduinoStarterKit) (_recommended for entry level, the starter kit includes hundreds of LEDs, resistors, capacitors, a breadboard, jump wires, battery snaps etc_).

### To revise some basic electronics:

Resistance (_R_) is measured in Ohms  
Potential difference (_V_) is measured in Volts  
Current (_I_) is measured in Amps

Ohm's law states _V = I * R_ 

![Circuit diagrams](http://hyperphysics.phy-astr.gsu.edu/hbase/electric/imgele/dcx6.gif)

### Circuits in Series

* Voltage is **different** across components
* Current is the **same** across components
* _Vtotal = V1 + V2_
* _Current total = I1 = I2_
* _Requivalent = R1 + R2_

### Circuits in  Parallel

* Voltage is the **same** across branches
* Current is the **different** across branches
* _Vtotal = V1 = V2_  
* _Current total = I1 + I2_  
* _1/Requivalent = 1/R1 + 1/R2_

The potential difference at +V on a closed circuit provides charge which then channels itself via routes depending on how much resistance it faces. If components are connected along a single wire (series) then the level of charge is constant as there is only one path. If there are multiple routes then the charge favours route with less obstacles (resistance), some of the charge still flows through other routes to ground.

The electrons in the circuit flow from ground to high voltage as they are negatively charged.

### Arduino Basics

Really the best place to begin is the [Arduino HomePage ](https://www.arduino.cc/en/Guide/HomePage). Once you have the IDE and libraries installed for your platform the [language reference](https://www.arduino.cc/en/Reference/HomePage) for _ino_ files is very useful. The first thing to note is the types of pins on your Arduino board; there's [digital pins](https://www.arduino.cc/en/Tutorial/DigitalPins) and [analogue pins](https://www.arduino.cc/en/Tutorial/AnalogInputPins).

#### Digital pin functions
~~~
pinMode(pinNum, INPUT/OUTPUT);  
digitalRead(pinNum);  
digitalWrite(pinNum, LOW/HIGH);  
analogWrite(pinNum, Value); (to digital pulse width modulation pins)
~~~

#### Analog pin function
~~~
analogRead(pinNum);  
~~~

#### Serial screen functions
~~~
Serial.begin(PortNum);  
Serial.print("test");
~~~

Each arduino sketch files contains a [_setup()_](https://www.arduino.cc/en/Reference/setup) and [_loop()_](https://www.arduino.cc/en/Reference/Loop) function.

### Arduino Projects

[See all current projects](https://blog.murraywynnes.com/arduino-projects/)
