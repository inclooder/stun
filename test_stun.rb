require 'socket'
require 'securerandom'

#dokumentacja https://tools.ietf.org/html/rfc3489

servers = [
  "stun.l.google.com:19302",
  "stun1.l.google.com:19302",
  "stun2.l.google.com:19302",
  "stun3.l.google.com:19302",
  "stun4.l.google.com:19302",
  "stun.ekiga.net:3478",
  "stun.ideasip.com:3478",
  "stun.schlund.de:3478",
  "stun.stunprotocol.org:3478",
  "stun.voiparound.com:3478",
  "stun.voipbuster.com:3478",
  "stun.voipstunt.com:3478",
].map do |addr|
  host, port = addr.split(':')
  { host: host, port: port.to_i }
end

class StunHeader
  MESSAGE_TYPES = {
    binding_request: 0x001,
    binding_response: 0x0101,
    binding_error_response: 0x0111,
    shared_secret_request: 0x002,
    shared_secret_response: 0x0102,
    shared_secret_error_response: 0x0112,
  }

  attr_reader :message_type, :message_length, :transaction_id

  def initialize(type, length = 0, transaction_id = SecureRandom.alphanumeric(16))
    @message_type = type
    @message_length = length
    @transaction_id = transaction_id
    puts transaction_id
  end

  def to_data
    [
      message_type,
      message_length,
      transaction_id
    ].pack('nna16')
  end

  def self.from_data(data)
    message_type, message_length, transaction_id = data.unpack('nna16')
    new(message_type, message_length, transaction_id)
  end
end

class StunAttribute
  attr_reader :type, :length, :value

  def self.from_data(data)
  end
end

header = StunHeader.new(StunHeader::MESSAGE_TYPES[:binding_request])

payload = header.to_data

puts payload.inspect
puts StunHeader.from_data(payload).inspect


host = '108.177.14.127'
port = 19302

socket = UDPSocket.new
iden = "#{host} #{port}"
puts "Testing #{iden}"
socket.connect(host, port)
puts socket.inspect
socket.send(payload, 0, host, port)
resp = socket.recv(1024)
puts "Response from #{iden} #{resp.inspect}"

resp_header = resp[0...20]
puts StunHeader.from_data(resp_header).inspect

