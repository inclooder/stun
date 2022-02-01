# Stun client

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'stun'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install stun

## Usage

```ruby
require 'stun'

socket = UDPSocket.new
client = Stun::Client.new(host: '108.177.14.127', port: 19302)
response = client.query(socket: socket)
response.ip # external ip
response.port # external port
```


## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/inclooder/stun.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
