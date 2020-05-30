require 'socket'
require 'securerandom'
require 'bindata'

#https://tools.ietf.org/html/rfc3489

module Stun
  class Client
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
      uint16 :message_length, initial_value: 0
      string :transaction_id, length: 16, initial_value: lambda { SecureRandom.alphanumeric(16) }
      buffer :attributes, type: :stun_message_attribute, length: lambda { message_length }, onlyif: lambda { message_length > 0 }

      def message_type_name
        MESSAGE_TYPES.fetch(message_type)
      end
    end

    def initialize(options = {})
      @host = options.fetch(:host, '108.177.14.127')
      @port = options.fetch(:port, 19302)
    end

    def query_address
      payload = StunMessage.new(message_type: 0x0001).to_binary_s
      socket = UDPSocket.new
      socket.connect(@host, @port)
      socket.send(payload, 0, @host, @port)
      resp = socket.recv(1024)

      msg = StunMessage.read(resp)
      attr = msg[:attributes][:attribute_value]
      {
        id: "#{attr[:ip_a]}.#{attr[:ip_b]}.#{attr[:ip_c]}.#{attr[:ip_d]}",
        port: attr[:port]
      }
    end
  end
end
