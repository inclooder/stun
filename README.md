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

TODO: Write usage instructions here

```ruby
require 'stun'

client = Stun::Client.new(host: '108.177.14.127', port: 19302)
client.query_address
```


## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/inclooder/stun.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
