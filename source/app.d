/*****
  written by Vladimir Shabunin
  Primitive websocket client implementation
  This code is public domain.
  You may use it for any purpose.
  This code has no warranties and is provided 'as-is'.
  *****/

import core.thread;
import std.string, std.conv, std.stdio;
import std.socket;
import std.base64;
import std.random;
import std.utf;
import std.bitmanip;
import std.digest.sha;

enum MyWsState {
  closed,
  ready
}

enum BUFF_SIZE = 2048;
enum MAX_MSGLEN = 65535;

class MyBasicWsClient {
  Socket sock;
  MyWsState state;

  this(string url) {
    auto i = indexOf(url, "://");
    if (i != -1) {
      if (icmp(url[0 .. i], "ws")) {
        throw new Exception("ws:// expected");
      }
      url = url[i + 3..$];
    }
    i = indexOf(url, '/');
    string domain;

    if (i == -1) {
      domain = url;
      url    = "/";
    } else {
      domain = url[0 .. i];
      url    = url[i .. $];
    }

    ushort port;
    i = indexOf(domain, ':');

    if (i == -1) {
      port = 80;
    }
    else {
      port   = to!ushort(domain[i + 1 .. $]);
      domain = domain[0 .. i];
    }
    sock = new TcpSocket(new InternetAddress(domain, port));
    sock.blocking = false;

    if (port != 80) {
      domain = domain ~ ":" ~ to!string(port);
    }

    string getReq = "";
    getReq ~= "GET " ~ url ~ " HTTP/1.0\r\n";
    getReq ~= "Host: " ~ domain ~ "\r\n";
    getReq ~= "Upgrade: websocket\r\n";
    getReq ~= "Connection: Upgrade\r\n";

    // generate random key
    ubyte[16] key;
    foreach(k; 0..15) {
      key[k] = cast(ubyte) uniform(0, 255);
    }

    string key64 = Base64.encode(key);

    getReq ~= "Sec-WebSocket-Key: " ~ key64 ~ "\r\n";
    getReq ~= "\r\n";

    // send handshake request
    sock.send(getReq);

    while (true) {
      char[] line;
      char[1] buf;
      while(sock.receive(buf)) {
        line ~= buf;
        if (buf[0] == '\n')
          break;
      }

      if (!line.length) {
        break;
      }
      if (line[0] == '\r' || line[0] == '\n') {
        break;
      }

      enum SecWebSocketAccept = "Sec-WebSocket-Accept:";
      auto j = line.indexOf(SecWebSocketAccept);
      if (j != -1) {
        // TODO: err handling
        auto k = line.split(":")[1].replace(" ", "").replace("\r", "").replace("\n", "");
        // expected
        auto swka = key64~"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        auto swkaSha1 = sha1Of(swka);
        string expectedKey = Base64.encode(swkaSha1);
        if(k != expectedKey) {
          throw new Exception("handshake failed");
        } else {
          break;
        }
      }
    }
    // TODO: protocol
    this.state = MyWsState.ready;
    onReady();
  }

  // this one from server impl
  void onMessage(char[] data) {
    //writeln("NOT correct UTF8 string?");
    auto bytes = cast(ubyte[]) data;
    bool fin = (bytes[0] & 0b10000000) != 0;
    if (!fin) {
      return;
      // no support for fragmented frames
    }

    int opcode = bytes[0] & 0b00001111;
    if (opcode != 0x01) {
      return;
      // support only text messages;
    }
    bool rsv = (bytes[0] & 0b01110000) == 0;
    if (!rsv) {
      // reserved frames should be 0
      //("reserverd 3 bits should be 0!");
      return;
    }

    bool mask = (bytes[1] & 0b10000000) != 0; 
    if (mask) {
      // mask should be false
      return;
    }

    // & 0111 1111
    ulong msglen = bytes[1];
    int offset = 2;
    if (msglen == 126) {
      msglen = bytes.peek!ushort(2);
      offset = 4;
    } else if (msglen == 127) {
      msglen = bytes.peek!ulong(2);
      offset = 10;
    }
    if (msglen > MAX_MSGLEN || msglen == 0) {
      return;
    }

    // try to receive whole message if there was not
    auto currentLen = data.length - offset;
    if (currentLen < msglen) {
      while (currentLen < msglen) {
        char[BUFF_SIZE] buf;
        auto datLength = sock.receive(buf[]);
        if (datLength > 0) {
          data ~= buf[0..datLength];
          currentLen += datLength;

          // if two and more messages arrived in one buffer chunk
          if (datLength < buf.length) {
            onMessage(buf[datLength..$]);
          }
          continue;
        }
      }

      // finally, when we receive full frame
      onMessage(data);
      return;
    }

    // to text
    ubyte[] decoded;
    decoded.length = msglen;
    decoded[0..msglen] = cast(ubyte[])data[offset..offset+msglen];

    string text = (cast(char[])decoded).toUTF8();
    // if whole frame or the end of fragmented
    onWsMessage(text);

    // if two or more messages arrived in one buffer
    auto expectedlen = offset + msglen;
    if (expectedlen < data.length) {
      onMessage(data[expectedlen..$]);
    }

    return;
  }

  // this one from server impl
  void sendWsMessage(string data) {
    ubyte[] encoded;
    auto offset = 0;
    auto msglen = data.length;
    if (msglen < 126) {
      offset = 2;
      encoded.length = offset + msglen;
      // fin = 1; opcode = 1;
      encoded[0] = cast(ubyte)0b10000001;
      // with mask bit
      encoded[1] = cast(ubyte)(data.length) | 0b10000000;
    } else if (msglen >= 126 && msglen <= 65535) {
      offset = 4;
      encoded.length = offset + msglen;
      encoded[0] = cast(ubyte)0b10000001;
      // with mask bit
      encoded[1] = cast(ubyte)(126) | 0b10000000;
      encoded.write!ushort(cast(ushort)msglen, 2);
    } else if (msglen > 65535) {
      offset = 10;
      encoded.length = offset + msglen;
      encoded[0] = cast(ubyte)0b10000001;
      // with mask bit
      encoded[1] = cast(ubyte)(127) | 0b10000000;
      encoded.write!ulong(cast(ulong)msglen, 2);
    }
    // generate 32bit mask
    ubyte[4] mask;
    foreach(k; 0..4) {
      mask[k] = cast(ubyte) uniform(0, 255);
    }
    encoded.length += mask.length;

    encoded[offset..offset+4] = mask[0..$];
    offset += 4;
    ubyte[] bytes = cast(ubyte[])data;
    // encode message
    for (auto i = 0; i < msglen; ++i) {
      encoded[i + offset] = cast(ubyte) (bytes[i] ^ mask[i % 4]);
    }
    sock.send(encoded);
  }
  void loop() {
    if (state == MyWsState.ready) {
      char[BUFF_SIZE] buf;
      auto l = sock.receive(buf[]);
      if (l > 0) {
        onMessage(buf[0..l]);
      } else if (l == 0) {
        //sock.close();
        state = MyWsState.closed;
        onClose();
      }
    }
  }

  void onReady() {
    // empty. should be overrided
  }
  void onClose() {
    // empty. should be overrided
  }
  void onWsMessage(string data) {
    // empty. should be overrided
  }
}

class MyCustomWsClient: MyBasicWsClient {
  this(string url) {
    super(url);
  }
  override void onReady() {
    writeln("ws ready");
  }
  override void onClose() {
    writeln("ws close");
  }
  override void onWsMessage(string data) {
    writeln("got message: ", data);
  }
}

void main(string[] args) {
  auto my = new MyCustomWsClient("ws://127.0.0.1:45000/");
  
  writeln("subscribing");
  my.sendWsMessage("[12, \"subscribe\", \"hello\"]");

  while(true) {
    my.loop();
    Thread.sleep(1.msecs);
  }
}
