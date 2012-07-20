# encoding: utf-8
# License:: Ruby
# Author:: Guillaume Pierronnet (mailto:guillaume.pierronnet@gmail.com)
# Website:: http://ruby-mp3info.rubyforge.org/

require "delegate"
require 'active_support/core_ext/numeric/bytes.rb'

if RUBY_VERSION[0..2] == "1.8"
  require "iconv"
  RUBY_1_8 = true
else
  RUBY_1_8 = false
end

require "mp3info/extension_modules"

class ID3v2Error < StandardError ; end

# This class can be used to decode id3v2 tags from files, like .mp3 or .ape for example.
# It works like a hash, where key represents the tag name as 3 or 4 upper case letters
# (respectively related to 2.2 and 2.3+ tag) and value represented as array or raw value.
# Written version is always 2.3.
class ID3v2 < DelegateClass(Hash)

  include Mp3Info::FrameList

  include Mp3Info::HashKeys

  # See id3v2.4.0-structure document, at section 4.
  TEXT_ENCODINGS = ["iso-8859-1", "utf-16", "utf-16be", "utf-8"]

  DEFAULT_PADDING = 2.kilobytes # default padding added when we rewrite a file. = allow small changes without rewriting the file

  # this is the position in the file where the tag really ends
  attr_reader :io_position

  # optim : if padding is enough, we'll not rewrite a complete mp3, but directly write into the original.
  attr_reader :rewrite_mp3 # important : this is evaluated during "to_bin"

  # tag size as specified in the id3 tag (= complete tag size without tag header)
  attr_reader :tag_length

  # :+lang+: for writing comments
  #
  # [DEPRECATION] :+encoding+: one of the string of +TEXT_ENCODINGS+,
  # use of :encoding parameter is DEPRECATED. In ruby 1.8, use utf-8 encoded strings for tags.
  # In ruby >= 1.9, strings are automatically transcoded from their originaloriginal  encoding.
  attr_reader :options

  # possible options are described above ('options' attribute)
  # you can access this object like an hash, with [] and []= methods
  # special cases are ["disc_number"] and ["disc_total"] mirroring TPOS attribute
  def initialize(options = {})

    # default options
    @options = {
      :lang => "ENG",
      :padding => true,
      :padding_size => DEFAULT_PADDING,
      :smart_padding => true,
      :minimum_tag_size => 0,
      :minimum_tag_size_callback => nil
    }

    # deprecation
    if @options[:encoding]
      warn("use of :encoding parameter is DEPRECATED. In ruby 1.8, use utf-8 encoded strings for tags.\n" +
           "In ruby >= 1.9, strings are automatically transcoded from their original encoding.")
    end

    @options.update(options)

    @hash = {}
    @hash_orig = {}
    super(@hash)
    @tag_length = 0
    @rewrite_mp3 = true
    @parsed = false
    @filesize = 0
    @version_maj = @version_min = nil
  end

  # does this tag has been correctly read ?
  def parsed?
    @parsed
  end

  # does this tag has been changed ?
  def changed?
    @hash.reject!{|k,v| !@hash_orig[k] && (v.nil? || v.to_s.empty?)} # when a frame was not originally present, setting it to nil or empty doesnt change the tag.
    @hash_orig != @hash
  end

  # full version of this tag (like "2.3.0") or nil
  # if tag was not correctly read
  def version
    if @version_maj && @version_min
      "2.#{@version_maj}.#{@version_min}"
    else
      nil
    end
  end

  ### gets id3v2 tag information from io object (must support #seek() method)
  def from_io(io)
    @io = io
    @filesize = @io.size rescue 0 # chab : rescue as i'm not sure of behaviour with stream
    original_pos = @io.pos
    @io.extend(Mp3Info::Mp3FileMethods)
    version_maj, version_min, flags = @io.read(3).unpack("CCB4")
    @unsync, ext_header, experimental, footer = (0..3).collect { |i| flags[i].chr == '1' }
    raise(ID3v2Error, "can't find version_maj ('#{version_maj}')") unless [2, 3, 4].include?(version_maj)
    @version_maj, @version_min = version_maj, version_min
    @tag_length = @io.get_syncsafe
    puts "tag size in file: #{@tag_length}" if $DEBUG

    @parsed = true
    begin
      case @version_maj
        when 2
          read_id3v2_2_frames
        when 3, 4
          # seek past extended header if present
          @io.seek(@io.get_syncsafe - 4, IO::SEEK_CUR) if ext_header
          read_id3v2_3_frames
      end
    rescue ID3v2Error => e
      warn("warning: id3v2 tag not fully parsed: #{e.message}")
    end
    @io_position = @io.pos
    puts "beginning of audio: #{@io_position}" if $DEBUG

    @hash_orig = @hash.dup
    #no more reading
    @io = nil
  end

  # dump tag for writing. Version is always 2.3.0
  def to_bin
    #TODO handle of @tag2[TLEN"]
    #TODO add of crc
    #TODO add restrictions tag

    tag = ""
    @hash.each do |k, v|
      next unless v
      next if v.respond_to?("empty?") and v.empty?

      # Automagically translate V2 to V3 tags
      k = TAG_MAPPING_2_2_to_2_3[k] if TAG_MAPPING_2_2_to_2_3.has_key?(k)

      # doesn't encode id3v2.2 tags, which have 3 characters
      next if k.size != 4

      # Output one flag for each array element, or one only if it's not an array
      [v].flatten.each do |value|
        data = encode_tag(k, value.to_s)
        #data << "\x00"*2 #End of tag

        tag << k[0,4]   # 4 characters max for frame key
        size = data.size
        unless RUBY_1_8
          size = data.dup.force_encoding("binary").size
        end
        tag << [size].pack("N") #+1 because of the language encoding byte
        tag << "\x00"*2 #flags
        tag << data
      end
    end

    # tag size with padding
    padding = padding_size(@tag_length, tag.size)
    tag_size = tag.size + padding

    tag_str = "ID3"
    tag_str << [ 3, 0, "0000" ].pack("CCB4") #version_maj, version_min, unsync, ext_header, experimental, footer
    tag_str << [to_syncsafe(tag_size)].pack("N")
    tag_str << tag
    tag_str << ("\x00" * padding) if padding>0
    tag_str
  end

  # ###############################
  # private methods
  # ###############################

  private

  #
  #
  #
  def padding_size(old_tag_size, new_tag_size)
    @rewrite_mp3 = true
    return 0 unless @options[:padding]

    # padding size
    if new_tag_size <= old_tag_size
      @rewrite_mp3 = false
      padding = old_tag_size - new_tag_size
    else
      padding = @options[:padding_size]
    end

    # smart padding : expand the padding to reach a minimum tag size
    if @options[:smart_padding]
      min_size = minimum_tag_size(@filesize)
      if (new_tag_size + padding < min_size)
        padding = (min_size - new_tag_size)
        @rewrite_mp3 = true
      end
    end

    padding
  end

  #
  #
  # This will affect the padding resulting size (we assume that artwork is commonly used in id3 => reason why we book hundreds of kb)
  #
  #   the bigger the original file is => the longer it will take to rewrite it => the bigger the padding should be to avoid that
  #
  #   Strategy also made acceptable because : the bigger the file, the less you'll care about the added overhead.
  #
  #
  def minimum_tag_size(filesize)
    # custom behaviour
    return @options[:minimum_tag_size_callback].call(filesize) if @options[:minimum_tag_size_callback]

    # default behaviour
    if @options[:minimum_tag_size]>0
      return @options[:minimum_tag_size]
    elsif filesize > 20.megabytes
      return 200.kilobytes
    elsif filesize > 5.megabytes
      return 100.kilobytes
    else
      return 0 # not really expensive to rewrite small files + booking less than a certain amount is useless (artwork)
    end
  end

  #
  #
  #
  def encode_tag(name, value)
    puts "encode_tag(#{name.inspect}, #{value.inspect})" if $DEBUG
    name = name.to_s

    if name =~ /^(W|TRCK)/
      transcoded_value = Mp3Info::EncodingHelper.convert_to(value, "utf-8", "iso-8859-1")
    elsif name =~ /^(COM|T|USLT)/
      transcoded_value = Mp3Info::EncodingHelper.convert_to(value, "utf-8", "utf-16")
    end

    case name
      when "COMM", "USLT"
        puts "encode COMM/USLT: lang: #{@options[:lang]}, value #{transcoded_value.inspect}" if $DEBUG
        s = [ 1, @options[:lang], "\xFE\xFF\x00\x00", transcoded_value].pack("ca3a*a*")
        return s
      when "WXXX"
        puts "encode WXXX: value #{transcoded_value.inspect}" if $DEBUG
        s = [ 1, "\xFE\xFF\x00\x00", transcoded_value].pack("ca*a*")
        return s
      when /^TRCK/
        return "\x00" + transcoded_value
      when /^T/
        unless RUBY_1_8
          transcoded_value.force_encoding("BINARY")
        end
        return "\x01" + transcoded_value
      when /^W/
        return transcoded_value.force_encoding("binary")
      else
        return value.force_encoding("binary")
    end
  end

  ### Read a tag from file and perform UNICODE translation if needed
  def decode_tag(name, raw_value)
    puts("decode_tag(#{name.inspect}, #{raw_value.inspect})") if $DEBUG
    if name =~ /^(T|COM|USLT|WXXX)/
      if name =~ /^(COM|USLT)/
        encoding_index, lang, raw_tag = raw_value.unpack("ca3a*")
        comment, out = raw_tag.split(encoding_index == 1 ? "\x00\x00" : "\x00", 2) rescue ["",""]
        puts "COM/USLT tag found. encoding: #{encoding_index} lang: #{lang} str: #{out.inspect}" if $DEBUG
      elsif name =~ /^(WXXX)/
        encoding_index, raw_tag = raw_value.unpack("ca*")
        comment, out = raw_tag.split(encoding_index == 1 ? "\x00\x00" : "\x00", 2) rescue ["",""]
        puts "WXXX tag found. encoding: #{encoding_index} str: #{out.inspect}" if $DEBUG
      else
        encoding_index = raw_value.getbyte(0) # language encoding (see TEXT_ENCODINGS constant)
        out = raw_value[1..-1]
      end
      # we need to convert the string in order to match
      # the requested encoding
      if encoding_index && TEXT_ENCODINGS[encoding_index] && out && name!='WXXX'
        if RUBY_1_8
          out = Mp3Info::EncodingHelper.convert_to(out, TEXT_ENCODINGS[encoding_index], "utf-8")
        else
          if encoding_index == 1
            out = Mp3Info::EncodingHelper.decode_utf16(out)
          else
            out.force_encoding(TEXT_ENCODINGS[encoding_index])
          end
          if out
            out.encode!("utf-8") rescue out.force_encoding('iso-8859-1').encode!('utf-8')
          end
        end
      end

      out.force_encoding(TEXT_ENCODINGS[0]).encode!("utf-8") if name=='WXXX' && out # wxxx's description depends on encoding_index, but content is always latin1

      if out
        # remove padding zeros for textual tags
        if RUBY_1_8
          r = /\0*$/
        else
          r = Regexp.new("\x00*$".encode(out.encoding))
        end
        out.sub!(r, '')
      end

      return out
    else
      return raw_value
    end
  end

  ### reads id3 ver 2.3.x/2.4.x frames and adds the contents to @tag2 hash
  ### NOTE: the id3v2 header does not take padding zero's into consideration
  def read_id3v2_3_frames
    loop do # there are 2 ways to end the loop : [1] & [2] below
      name = @io.read(4)
      if name.nil? || name.getbyte(0) == 0 || name == "MP3e" #bug caused by old tagging application "mp3ext" ( http://www.mutschler.de/mp3ext/ )
        @io.seek(-4, IO::SEEK_CUR)    # [1] find a padding zero
	      seek_to_v2_end
        break
      else
	      if @version_maj == 4
	        size = @io.get_syncsafe
	      else
	        size = @io.get32bits
	      end
        flags = frame_flags(@io.read(2))
        puts "name '#{name}' size #{size}" if $DEBUG
        add_value_to_tag2(name, size, flags[:unsync] || @unsync, flags[:data_length_indicator])
      end
      break if @io.pos >= (@tag_length+10) # [2] reach tag_size as specified in header (+10 = header size)
    end
  end

  ### reads id3 ver 2.2.x frames and adds the contents to @tag2 hash
  ### NOTE: the id3v2 header does not take padding zero's into consideration
  def read_id3v2_2_frames
    loop do
      name = @io.read(3)
      if name.nil? || name.getbyte(0) == 0
        @io.seek(-3, IO::SEEK_CUR)
	      seek_to_v2_end
        break
      else
        size = (@io.getbyte << 16) + (@io.getbyte << 8) + @io.getbyte
	      add_value_to_tag2(name, size, @unsync)
        break if @io.pos >= (@tag_length+10) # (+10 = header size)
      end
    end
  end

  ### Add data to tag2["name"]
  ### read lang_encoding, decode data if unicode and
  ### create an array if the key already exists in the tag
  def add_value_to_tag2(name, size, unsync, data_length_indicator = false)
    puts "add_value_to_tag2, unsync #{unsync}" if $DEBUG

    if size > 50_000_000
      raise ID3v2Error, "tag size is > 50_000_000"
    end

    data_length = @io.get_syncsafe if data_length_indicator # skip 4 bytes data_length_indicator if any
    data_io = @io.read(size - (data_length_indicator ? 4 : 0))

    data = decode_tag(name, unsync ? resync(data_io) : data_io)

    if data && !data.empty?
      if self.keys.include?(name)
        if self[name].is_a?(Array)
          unless self[name].include?(data)
            self[name] << data
          end
        else
          self[name] = [ self[name], data ]
        end
      else
        self[name] = data
      end

      if name == "TPOS" && data =~ /(\d+)\s*\/\s*(\d+)/
        self["disc_number"] = $1.to_i
        self["disc_total"] = $2.to_i
      end
    end

    puts "self[#{name.inspect}] = #{self[name].inspect}" if $DEBUG
  end

  def frame_flags(data)
    flags = {
      :unsync => false,
      :data_length_indicator => false
    }
    begin
      bits = data.unpack("B*")[0]
      flags[:unsync] = bits[14].chr == '1'
      flags[:data_length_indicator] = bits[15].chr == '1'
    rescue
      # do nothing
    end
    flags
  end

  #
  # re-sync unsynched content
  #
  def resync(data)
    data.gsub("\xFF\x00".force_encoding('binary'), "\xFF".force_encoding('binary'))
  end

  ### runs thru @file one char at a time looking for best guess of first MPEG
  ###  frame, which should be first 0xff byte after id3v2 padding zero's
  def seek_to_v2_end
    until @io.getbyte == 0xff
      raise ID3v2Error, "got EOF before finding id3v2 end" if @io.eof?
    end
    @io.seek(-1, IO::SEEK_CUR)
  end

  ### convert an 32 integer to a syncsafe string
  def to_syncsafe(num)
    ( (num<<3) & 0x7f000000 )  + ( (num<<2) & 0x7f0000 ) + ( (num<<1) & 0x7f00 ) + ( num & 0x7f )
  end

end

