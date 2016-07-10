---
layout: post
title: Initiating Arduino
subtitle: Introduction to basic level Arduino programming
published: true
---

I rememeber the excitement when learning how logic gates and flip flops work in school, it's been a while since then so decided to try re-kindle the magic by learning how to program Arduino. I originally chose the Raspberry Pi to learn but it only became a proxy for our media hub, therefore I'm deciding to go down the microelectronics route and adopt an unsuspecting [Arduino Uno](https://www.arduino.cc/en/Main/ArduinoStarterKit) (_recomended for entry level and with the starter kit which includes hundreds of LEDs, resistors, capacitors, a breadboard, jump wires, battery snaps etc_).

### To revise some basic electronics:

Resistence _R_ is measured in Ohms
Potential difference _V_ is measured in Volts
Current _I_ is measured in Amps

Ohm's law states _V = I * R_ 

### Circuits in Series

* Voltage is **different** accross components
* Current is the **same** accross components

_Vtotal = V1 + V2 + V3_  
_Current total = I1 = I2 = I3_  
_Rtotal = R1 + R2 + R3_

### Circuits in  Parallel

* Voltage is the **same** accross branches
* Current is the **different** accross branches

_Vtotal = V1 + V2 + V3_  
_Current total = I1 = I2 = I3_  
_1/Rtotal = 1/R1 + 1/R2 + 1/R3_

The voltage from the battery provides charge, imagine the charge of the circuit channeling itself like a liquid via different routes depending on how much resistence it faces. If components are connected along a single wire (series) then the level of charge is constant as there is only one path. If there are multiple routes then the charge favours route with less obstacles (resistence), but of course some will still flow through other routes to ground.

The electrons in the circuit flow from ground to high voltage as they are negatively charged.

### Arduino Basics

Really the best place to begin is the [Arduino HomePage ](https://www.arduino.cc/en/Guide/HomePage). Once you have the IDE and libraries installed for your platform the [language reference](https://www.arduino.cc/en/Reference/HomePage) for _ino_ files is very usefull. The first thing to note is the types of pins on your Arduino board; there's [digital pins](https://www.arduino.cc/en/Tutorial/DigitalPins) and [analogue pins](https://www.arduino.cc/en/Tutorial/AnalogInputPins).

#### digital pin functions
* pinMode(pinNum, INPUT/OUTPUT);  
* digitalRead(pinNum);  
* digitalWrite(pinNum, LOW/HIGH);  
* analogWrite(pinNum, Value); (to digital [Pulse Width Modulation](https://www.arduino.cc/en/Tutorial/PWM) pin)

#### analog pin function
* alaogRead(pinNum);

#### serial screen functions
* Serial.begin(PortNum);  
* Serial.print("test");

Each arduino skecth files contains a _setup()_ and _loop()_ function.

### Arduino Projects

[See all my current projects](https://blog.murraywynnes.com/arduino-projects/)
