require "ffi"
require "base64"
require "json"
require "logger"
require "base64"
require "uri"
require "open3"

###  sdk start
module GoApi
  extend FFI::Library
  ffi_lib "./foundation-api.so"

  class Example < FFI::Struct
    # This must be completely in sync with the C struct defined in Go code.
    layout :id, :int, :prefix, :pointer

    def initialize(prefix, id)
      self[:prefix] = FFI::MemoryPointer.from_string(prefix)
      self[:id] = id
    end

    # This feels convoluted, but it hides the fact that our function is loaded
    # outside of the "struct mirror" class.
    def greet
      Portal.greet(self)
    end
  end

  attach_function :send_file_event, [:string, :string, :string, :string], :strptr
  attach_function :get_messages, [], :strptr
  attach_function :send_message, [:string], :strptr
  attach_function :file_cache_write, [:string], :strptr
  attach_function :file_cache_read, [:string, :string], :strptr
  attach_function :file_cache_read, [:string, :string], :strptr
  attach_function :send_complete_events, [], :strptr
  attach_function :send_folder_event, [:string, :string, :string, :string], :strptr
end

module Utils
  class Subprocess
    def initialize(cmd, &block)
      Open3.popen3(cmd) do |stdin, stdout, stderr, thread|
        { :out => stdout, :err => stderr }.each do |key, stream|
          Thread.new do
            until (line = stream.gets).nil?
              if key == :out
                yield line, nil, thread if block_given?
              else
                yield nil, line, thread if block_given?
              end
            end
          end
        end
        thread.join # don't exit until the external process is done
        exit_code = thread.value
        if (exit_code != 0)
          puts("Failed to execute_cmd #{cmd} exit code: #{exit_code}")
          Kernel.exit(false)
        end
      end
    end
  end
end

class Helper
  def self.run(cmd, chdir = File.dirname(__FILE__))
    puts("run: #{cmd}")
    Utils::Subprocess.new cmd do |stdout, stderr, thread|
      puts "\t#{stdout}"
      if (stderr.nil? == false)
        puts "\t#{stderr}"
      end
    end
  end

  def self.get_env(name, default)
    if "#{ENV[name]}" == ""
      return default
    end
    return ENV[name]
  end

  def self.get_env_or_fail(name)
    val = Helper.get_env(name, "")
    if val == ""
      puts("expected environment variable not set: #{name}")
      exit(1)
    end
    return val
  end

  def self.valid_json?(json)
    JSON.parse(json)
    true
  rescue JSON::ParserError, TypeError => e
    false
  end

  def self.make_events_hash(b64event)
    if "#{b64event}" == ""
      puts("missing event data")
      exit(1)
    end
    events = Base64.decode64(b64event)

    if Helper.valid_json?(events) == false
      puts("invalid event data")
      exit(1)
    end
    eventsHash = JSON.parse(events)
    return eventsHash
  end
end

class Controller
  def initialize(plugin)
    @api = FoundationApi.new()
    @log = Logger.new(STDOUT)
    @config = Config.new()
    @plugin = Plugin.new(@api, @log, @config)
  end

  def run()
    keep_reading = true
    @log.info("starting controller loop")
    while keep_reading
      rtn = @api.get_messages()
      @log.info("rtn: #{rtn.message} #{rtn.error} #{rtn.exit_code}")
      # convert message to fileevent
      hash = JSON.parse(rtn.message)
      hash["items"].each do |item|
        @log.info("message kind: #{item["kind"]}")
        case item["kind"]
        when "FileEvent"
          @log.info("FileEvent")
          event = FileEvent.new(item)
          @plugin.on_file_event(event)
        when "FolderEvent"
          @log.info("FolderEvent")
          event = FolderEvent.new(item)
          @plugin.on_folder_event(event)
        when "CompleteEvent"
          @log.info("CompleteEvent")
          event = CompleteEvent.new(item)
          @plugin.on_complete_event(event)
          keep_reading = false
        else
          @log.info("unknown event kind: #{item["kind"]}")
        end
      end
    end
    @log.info("ending controller loop sending complete event")
    res2 = @api.send_complete_events()
    if res2.exit_code != 0
      @log.error("failed to send complete event: #{res2.error} #{res2.exit_code}")
    end
  end
end

class Response
  attr_accessor :payload, :error, :exit_code

  def initialize(payload, error, exit_code)
    @payload = payload
    @error = error
    @exit_code = exit_code
  end
end

class FileWriteResult
  attr_accessor :destination, :error, :exit_code

  def initialize(response)
    @error = response.error
    @exit_code = response.exit_code
    hash = JSON.parse(response.payload)
    @destination = hash["destination"]
  end
end

class MetaData
  attr_accessor :name, :created, :id, :runid, :tags, :label

  def initialize(hash)
    @name = hash["name"]
    @created = hash["created"]
    @id = hash["id"]
    @runid = hash["runid"]
    @tags = hash["tags"]
    @label = hash["label"]
  end
end

class FolderEvent
  attr_accessor :kind, :version, :metadata, :origin, :path, :folder, :originalpath, :origin

  def initialize(hash)
    @kind = hash["kind"]
    @version = hash["version"]
    @metadata = MetaData.new(hash["metadata"])
    @origin = hash["origin"]
    @path = hash["path"]
    @folder = hash["folder"]
    @originalpath = hash["originalpath"]
    @origin = hash["origin"]
  end
end

class FileEvent
  attr_accessor :kind, :version, :metadata, :origin, :path, :filename, :originalpath, :origin

  def initialize(hash)
    @kind = hash["kind"]
    @version = hash["version"]
    @metadata = MetaData.new(hash["metadata"])
    @origin = hash["origin"]
    @path = hash["path"]
    @filename = hash["filename"]
    @originalpath = hash["originalpath"]
    @origin = hash["origin"]
  end
end

class FileReadResult
  attr_accessor :error, :exit_code

  def initialize(response)
    @error = response.error
    @exit_code = response.exit_code
  end
end

class GetMessageResult
  attr_accessor :message, :error, :exit_code

  def initialize(response)
    @error = response.error
    @exit_code = response.exit_code
    @message = response.payload
  end
end

class SendMessageResult
  attr_accessor :message, :error, :exit_code

  def initialize(response)
    @error = response.error
    @exit_code = response.exit_code
    @message = response.payload
  end
end

class SendFolderResult
  attr_accessor :message, :error, :exit_code

  def initialize(response)
    @error = response.error
    @exit_code = response.exit_code
    @message = response.payload
  end
end

class SendCompleteResult
  attr_accessor :message, :error, :exit_code

  def initialize(response)
    @error = response.error
    @exit_code = response.exit_code
    @message = response.payload
  end
end

class Config
  def initialize()
    @config_path = Helper.get_env("X_CONFIG", "/etc/plugin/config.json")
    @config = load()
  end

  def load()
    file = File.read(@config_path)
    config = JSON.parse(file)
    return config
  end

  def get(name)
    rtn = @config[name]
    if rtn == ""
      puts("plugin configuration is not valid, missing: #{name}")
      exit(2)
    end
    return rtn
  end
end

class FoundationApi
  def initialize()
  end

  def pase_response(response)
    data = JSON.parse(response)

    rtn = Response.new(data["payload"], data["error"], data["exit_code"])
    return rtn
  end

  def display_response(response)
    puts("payload: #{response.payload}")
    puts("error: #{response.error}")
    puts("exit_code: #{response.exit_code}")
  end

  def get_messages()
    d, e = GoApi.get_messages()
    parsed = pase_response(d)
    display_response(parsed)
    return GetMessageResult.new(parsed)
  end

  def send_message(data)
    d, e = GoApi.send_message(data)
    parsed = pase_response(d)
    display_response(parsed)
    return SendMessageResult.new(parsed)
  end

  def send_file_event(path, filename, originalpath, origin)
    d, e = GoApi.send_file_event(path, filename, originalpath, origin)
    parsed = pase_response(d)
    display_response(parsed)
    return SendMessageResult.new(parsed)
  end

  def send_folder_event(path, folder, originalpath, origin)
    d, e = GoApi.send_folder_event(path, folder, originalpath, origin)
    parsed = pase_response(d)
    display_response(parsed)
    return SendFolderResult.new(parsed)
  end

  def file_cache_read(uri, destination)
    d, e = GoApi.file_cache_read(uri, destination)
    parsed = pase_response(d)
    display_response(parsed)
    return FileReadResult.new(parsed)
  end

  def file_cache_write(filename)
    d, e = GoApi.file_cache_write(filename)
    parsed = pase_response(d)
    display_response(parsed)
    return FileWriteResult.new(parsed)
  end

  def send_complete_events()
    d, e = GoApi.send_complete_events()
    parsed = pase_response(d)
    display_response(parsed)
    return SendCompleteResult.new(parsed)
  end
end

### sdk end
