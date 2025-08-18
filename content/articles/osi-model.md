+++
date = '2025-08-18T10:24:25+05:30'
draft = false 
title = 'The OSI Model'
+++

# OSI Model 

Note: You can view the packet capture in my github repository. This is meant to be supplementary material for my presentation, so don't worry if it's not clear. I will update it later with the full explanation.

The Open Systems Interconnection (OSI) model is a **reference model** developed by the International Organization for Standardization (ISO) that "provides a common basis for the coordination of standards development for the purpose of systems interconnection.

The **TCP/IP** Model is what is widely used in practical networking and forms the foundation of the internet.

For the actual specifications, we can view the RFC's: 

- [RFC 1122](https://www.rfc-editor.org/rfc/rfc1122)
- [RFC 1123](https://www.rfc-editor.org/rfc/rfc1123)

These documents give a structured specification for implementation.


## The seven layers of the OSI model

| S.No | Layer | Role | Example |
| ---  | ---   | ---- | ---               |
| 7    | Application Layer | interacts directly with the user data, think of it as an interface for the applications to use. | HTTP,FTP,SMTP,SSH |
| 6    | Presentation Layer | makes the data presentable for the application layer, responsible for translation,encryption or compression | TLS | 
| 5    | Session Layer | opening, maintaing and closing communication between the two devices. It synchornizes the data transfer and keeps the connection alive | TCP |
| 4    | Transport Layer | responsible for end-to-end communication. This includes taking data from the session layer and breaking it up into chunks called segments before sending it to layer 3. | TCP | 
| 3    | Network Layer   | facilitates data transfer between two different networks, breaks up segments into smaller units called packets. Finds the best physical path(routing) | IP,ICMP | 
| 2    | Data Link layer | physical addressing on the local network segment, finding where to deliver the data | MAC addresses, ethernet frames | 
| 1    | Physical Layer  | The physical medium/connection between the devices such as cables and switches | | 

## The TCP/IP model 

| S.No | Layer | Role | Example |
| ---  | ---   | ---- | ---     |
| 4    | Application Layer | OSI model’s Application, Presentation, and Session layers. | HTTP, FTP, SMTP |
| 3    | Transport Layer   | provides reliable communication between devices | UDP,TCP | 
| 2    | Internet Layer    | manages routing, ensuring data packets reach the correct destination.  | IP,ICMP | 
| 1    | Network Access Layer |  Also known as the Link layer, it covers physical transmission and access to network media. | Ethernet, Wi-Fi | 

The TCP/IP model is practical, straightforward, and essential for modern networking, while the OSI model is valued for its clarity and is a powerful tool for diagnosing network issues.

# Understanding how protocols work 

They are a standard way for computers to communicate with each other. Just like languages for us, computers have protocols.

They define the "grammar" and structure of the message, such as:
- what does this part of the packet signify? 
- in what structure should I send the message?

We will be directly communicating with the protocol using `netcat`
netcat is a simple unix utility which reads and writes data across network connections, using TCP or UDP protocol.
[https://www.commandlinux.com/man-page/man1/nc.1.html](https://www.commandlinux.com/man-page/man1/nc.1.html)

# The two generals' problem 

![image](2-generals.png)


TCP cannot guarantee state consistency between endpoints

# A Practical example with Wireshark

I will be sending a test email to myself on localhost using the SMTP protocol. SMTP works on port 25 by default, lets connect to it using netcat 

`nc localhost 25`

```
[quix@quixel osi-model]$ nc localhost 25
220 quixel.localdomain ESMTP Postfix
HELO localhost
250 quixel.localdomain
MAIL FROM:<me@localhost> 
250 2.1.0 Ok
RCPT TO:<quix@localhost>
250 2.1.5 Ok
DATA
354 End data with <CR><LF>.<CR><LF>
subject: test mail

This is a test mail to demonstrate the OSI model
.
250 2.0.0 Ok: queued as 406BF140A8C
QUIT
221 2.0.0 Bye
```



- **HELO/EHLO** - initiates the SMTP session. 
- **MAIL FROM** - senders email address 
- **RCPT TO** - receivers mail 
- **DATA** - start of the email message body, end with a `.`
- **QUIT** - end the SMTP session

Mails are usually stored in `/var/spool/mail/<username>`

