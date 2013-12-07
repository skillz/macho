module MachO

  MH_MAGIC = 0xFEEDFACE
  MH_CIGAM = 0xCEFAEDFE
  MH_MAGIC_64 = 0xFEEDFACF
  MH_CIGAM_64 = 0xCFFAEDFE
  FAT_MAGIC = 0xCAFEBABE
  FAT_CIGAM = 0xBEBAFECA
  LC_ENCRYPTION_INFO = 0x21
  LC_UUID	= 0x1b

  # Represents a Mach-O load command.
  class LoadCmd
    attr_reader :cmd
    attr_reader :cmdsize

    # LC_ENCRYPTION_INFO-only
    attr_reader :cryptoff
    attr_reader :cryptsize
    attr_reader :cryptid

    # LC_UUID
    attr_reader :uuid

    def initialize(io, little_endian, obj64)
      @little_endian = little_endian
      @obj64 = obj64
      self.parse(io)
    end

    def parse(io)
      # Record our initial position so we can perform a relative seek over
      # this entire command once we're done (partially) reading its fields.
      cmd_start = io.pos

      # All commands start with an identifier and size field.
      @cmd, @cmdsize = io.read(8).unpack(MachO.format(@little_endian) * 2)

      # /*
      #  * The encryption_info_command contains the file offset and size of an
      #  * of an encrypted segment.
      #  */
      # struct encryption_info_command {
      #    uint32_t cmd;        /* LC_ENCRYPTION_INFO */
      #    uint32_t cmdsize;    /* sizeof(struct encryption_info_command) */
      #    uint32_t cryptoff;   /* file offset of encrypted range */
      #    uint32_t cryptsize;  /* file size of encrypted range */
      #    uint32_t cryptid;    /* which enryption system,
      #                            0 means not-encrypted yet */
      # };
      if @cmd == LC_ENCRYPTION_INFO
        @cryptoff, @cryptsize, @cryptid = io.read(12).unpack(
            MachO.format(@little_endian) * 3)
      end

      if @cmd == LC_UUID
        @uuid = io.read(16).unpack('H*').join()
      end

      # Seek to the end of this command (and the start of the next structure).
      io.seek(cmd_start + @cmdsize)

      self
    end
  end

  # Represents a Mach-O executable.
  class MachOExec

    attr_reader :offset
    attr_reader :magic
    attr_reader :cputype
    attr_reader :cpusubtype
    attr_reader :filetype
    attr_reader :cmds
    attr_reader :sizeofcmds
    attr_reader :flags
    attr_reader :uuid

    def initialize(io)
      self.parse(io)
    end

    def parse(io)
      @offset = io.pos

      @magic = io.read(4).unpack('N')[0]

      @little_endian = [MH_CIGAM, MH_CIGAM_64].include?(magic)
      @obj64 = [MH_MAGIC_64, MH_CIGAM_64].include?(magic)

      # /*
      #  * The 32-bit mach header appears at the very beginning of the object file for
      #  * 32-bit architectures.
      #  */
      # struct mach_header {
      #   uint32_t  magic;          /* mach magic number identifier */
      #   cpu_type_t  cputype;      /* cpu specifier */
      #   cpu_subtype_t cpusubtype; /* machine specifier */
      #   uint32_t  filetype;       /* type of file */
      #   uint32_t  ncmds;          /* number of load commands */
      #   uint32_t  sizeofcmds;     /* the size of all the load commands */
      #   uint32_t  flags;          /* flags */
      # };
      @cputype, @cpusubtype, @filetype, ncmds, @sizeofcmds, @flags =
          io.read(24).unpack(MachO.format(@little_endian) * 6)
      ext64bit = io.read(4).unpack(MachO.format(@little_endian)) if @obj64

      # Read all of the individual load commands.
      @cmds = (1..ncmds).map do |i|
        lcd = LoadCmd.new(io, @little_endian, @obj64)

        if lcd.cmd == LC_UUID
          @uuid = lcd.uuid
        end
        lcd
      end

      self
    end
  end

  # Represents a single architecture in a fat binary table.
  class FatArch
    attr_reader :cputype
    attr_reader :cpusubtype
    attr_reader :offset
    attr_reader :size
    attr_reader :align

    def initialize(io, little_endian)
      @little_endian = little_endian
      self.parse(io)
    end

    def parse(io)
      # struct fat_arch {
      #   cpu_type_t  cputype;      /* cpu specifier (int) */
      #   cpu_subtype_t cpusubtype; /* machine specifier (int) */
      #   uint32_t  offset;         /* file offset to this object file */
      #   uint32_t  size;           /* size of this object file */
      #   uint32_t  align;          /* alignment as a power of 2 */
      # };

      @cputype, @cpusubtype, @offset, @size, @align =
          io.read(20).unpack(MachO.format(@little_endian) * 5)
      #puts "FatArch cputype #{@cputype} size #{@size.to_s(16)} offset #{@offset.to_s(16)}"
      self
    end
  end

  # Represents the fat binary structure used to indicate that an executable
  # supports multiple architectures.
  class Fat
    attr_reader :archs

    def initialize(io, little_endian)
      @little_endian = little_endian
      self.parse(io)
    end

    def parse(io)
      # struct fat_header {
      #   uint32_t  magic;      /* FAT_MAGIC */
      #   uint32_t  nfat_arch;  /* number of structs that follow */
      # };
      io.seek(4) # skip magic
      count = io.read(4).unpack(MachO.format(@little_endian))[0]

      # Read the array of architectures from the fat binary header.
      @archs = Array.new(count) { |i| FatArch.new(io, @little_endian) }

      self
    end
  end

  # A Mach-O executable with support for multiple architectures.
  class Executable

    # Get the fat binary architecture table (if available).
    attr_reader :fat

    # Get the array of executable architectures.
    attr_reader :archs

    def initialize(file)
      unless file.respond_to?(:seek)
        file = File.new(file, 'r')
      end
      self.parse(file)
    end

    def parse(io)
      # The magic header value indicates the executable type.
      magic = io.read(4).unpack('N')[0]
      if [FAT_MAGIC, FAT_CIGAM].include?(magic)
        little_endian = FAT_CIGAM == magic
        # This is a fat binary with multiple Mach-O architectures.
        @fat = Fat.new(io, little_endian)
        # Parse each Mach-O architecture based on its offet in the binary.
        @archs = @fat.archs.collect do |arch|
          io.seek(arch.offset)
          MachOExec.new(io)
        end
      elsif [MH_MAGIC, MH_CIGAM, MH_MAGIC_64, MH_CIGAM_64].include?(magic)
        # This is a non-fat binary with a single Mach-O architecture.
        # Reset our IO stream so the start of the Mach-O header.
        io.seek(-4, IO::SEEK_CUR)
        @archs = [MachOExec.new(io)]
      end

      puts "arch magic #{magic.to_s(16)} FAT : #{[FAT_MAGIC, FAT_CIGAM].include?(magic)}"

      self
    end
  end

  # Simulate an encryption pass over an existing Mach-O executable.  This is
  # done by extracting the encryption parameters defined by the architectures'
  # LC_ENCRYPTION_INFO load commands and filling their encryption blocks with
  # random bytes.
  def self.simulate_encrypt(filename)
    file = File.open(filename, 'r+')
    exec = Executable.new(file)

    for macho in exec.archs
      arch_offset = macho.offset
      data_offset = arch_offset + macho.sizeofcmds

      for cmd in macho.cmds do
        if cmd.cmd == LC_ENCRYPTION_INFO
          random_bytes = Array.new(cmd.cryptsize)
          random_bytes.fill { rand(256) }

          file.seek(data_offset + cmd.cryptoff)
          file.write(random_bytes.pack('c*'))
        end
      end
    end
  end

  def self.format(little_endian)
    little_endian ? 'V' : 'N'
  end
end

# test for multi/single arch binary uuid extractions
if __FILE__ == $0
  exec = MachO::Executable.new(ARGV[0])
  exec.archs.each do |arch|
    puts "magic #{arch.magic.to_s(16)}, uuid #{arch.uuid}"
  end
  puts "Binary contains %d architecture(s)" % exec.archs.length
end


