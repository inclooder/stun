#!/usr/bin/ruby
require 'socket'
require 'securerandom'
require 'bindata'

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

class StunMessageHeader < BinData::Record
  MESSAGE_TYPES = {
    0x0001 => :binding_request,
    0x0101 => :binding_response,
    0x0111 => :binding_error_response,
    0x0002 => :shared_secret_request,
    0x0102 => :shared_secret_response,
    0x0112 => :shared_secret_error_response
  }.freeze

  endian :big

  uint16 :message_type
  uint16 :message_length
  string :transaction_id, length: 16

  def message_type_name
    MESSAGE_TYPES.fetch(message_type)
  end
end

class AddressAttributeValue < BinData::Record
  endian :big

  skip length: 1
  uint8 :family
  uint16 :port
  uint8 :ip_a
  uint8 :ip_b
  uint8 :ip_c
  uint8 :ip_d

  def ip
    [ip_a, ip_b, ip_c, ip_d].map(&:to_s).join('.')
  end
end

class MappedAddress < AddressAttributeValue
end

class ResponseAddress < AddressAttributeValue
end

class StunMessageAttribute < BinData::Record
  VALUE_TYPES = {
    0x0001 => :mapped_address,
    0x0002 => :response_address,
    0x0003 => :change_request,
    0x0004 => :source_address,
    0x0005 => :changed_address,
    0x0006 => :username,
    0x0007 => :password,
    0x0008 => :message_integrity,
    0x0009 => :error_code,
    0x000A => :unknown_attributes,
    0x000B => :reflected_from,
  }.freeze

  endian :big

  uint16 :value_type
  uint16 :value_length
  # buffer :attribute_value, type: :uint8, length: :value_length
  choice :attribute_value, selection: lambda { value_type }, choices: {
    0x0001 => :mapped_address,
    0x0002 => :response_address,
  }

  def value_type_name
    VALUE_TYPES.fetch(value_type)
  end
end

class StunMessage < BinData::Record
  endian :big
  stun_message_header :header
  buffer :attributes, type: :stun_message_attribute, length: lambda { header.message_length }
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
msg = StunMessage.read(resp)
puts "Response #{msg.inspect}"
puts "MessageType #{msg.header.message_type_name}"

puts "Response from #{iden} #{resp.inspect}"
