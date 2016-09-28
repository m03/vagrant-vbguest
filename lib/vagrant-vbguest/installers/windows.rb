module VagrantVbguest
  module Installers
    # A basic Installer implementation for vanilla or
    # unknown Windows based systems.
    class Windows < Base

      # A helper method to cache the result of {Vagrant::Guest::Base#distro_dispatch}
      # which speeds up Installer detection when having lots of Windows based
      # Installer classes to check. Vagrant does not differentiate between Windows
      # releases at present, but may in the near future. 
      #
      # @see {Vagrant::Guest::Windows#distro_dispatch}
      def self.distro(vm)
        @@distro ||= {}
        @@distro[ vm_id(vm) ] ||= distro_name vm
      end

      # Matches if the operating system name prints "Windows"
      # Raises an Error if this class is beeing subclassed but
      # this method was not overridden. This is considered an
      # error because, subclassed Installers usually indicate
      # a more specific distributen like 'ubuntu' or 'arch' and
      # therefore should do a more specific check.
      def self.match?(vm)
        raise Error, :_key => :do_not_inherit_match_method if self != Windows
        communicate_to(vm).test("test -d $Env:SystemRoot")
      end

      # Reads the `/etc/os-release` for the given `Vagrant::VM` if present, and
      # returns it's config as a parsed Hash. The result is cached on a per-vm basis.
      #
      # @return [Hash|nil] The os-release configuration as Hash, or `nil if file is not present or not parsable.
      def self.os_release(vm)
        @@os_release_info ||= {}
        if !@@os_release_info.has_key?(vm_id(vm)) && communicate_to(vm).test("test -f /etc/os-release")
          osr_raw = communicate_to(vm).download("/etc/os-release")
          osr_parsed = begin
            VagrantVbguest::Helpers::OsRelease::Parser.(osr_raw)
          rescue VagrantVbguest::Helpers::OsRelease::FormatError => e
            vm.env.ui.warn(e.message)
            nil
          end
          @@os_release_info[vm_id(vm)] = osr_parsed
        end
        @@os_release_info[vm_id(vm)]
      end

      def os_release
        self.class.os_release(vm)
      end

      # The temporary path where to upload the iso file to.
      # Configurable via `config.vbguest.iso_upload_path`.
      # Defaults the temp path to `$($Env:Temp)\\VBoxGuestAdditions.iso`
      # for all Windows based systems.
      def tmp_path
        options[:iso_upload_path] || '$($Env:Temp)\\VBoxGuestAdditions.iso'
      end

      # Mount point for the iso file.
      # Configurable via `config.vbguest.iso_mount_point`.
      # defaults to `D:\\` for all Windows based systems.
      def mount_point
        # populated by mount_iso
        options[:iso_mount_point] || 'D:\\'
      end

      # A generic way of installing GuestAdditions assuming all
      # dependencies on the guest are installed
      #
      # @param opts [Hash] Optional options Hash which might get passed to {Vagrant::Communication::WinRM#execute} and friends
      # @yield [type, data] Takes a Block like {Vagrant::Communication::Base#execute} for realtime output of the command being executed
      # @yieldparam [String] type Type of the output, `:stdout`, `:stderr`, etc.
      # @yieldparam [String] data Data for the given output.
      def install(opts=nil, &block)
        env.ui.warn I18n.t("vagrant_vbguest.errors.installer.generic_windows_installer", distro: self.class.distro(vm)) if self.class == Windows
        upload(iso_file)
        mount_iso(opts, &block)
        execute_installer(opts, &block)
        unmount_iso(opts, &block) unless options[:no_cleanup]
      end

      # @param opts [Hash] Optional options Hash which might get passed to {Vagrant::Communication::WinRM#execute} and friends
      # @yield [type, data] Takes a Block like {Vagrant::Communication::Base#execute} for realtime output of the command being executed
      # @yieldparam [String] type Type of the output, `:stdout`, `:stderr`, etc.
      # @yieldparam [String] data Data for the given output.
      def running?(opts=nil, &block)
        opts = {
          :sudo => true
        }.merge(opts || {})
        communicate.test('lsmod | grep vboxsf', opts, &block)
      end

      # This overrides {VagrantVbguest::Installers::Base#guest_version}
      # to also query the `VBoxService` on the host system (if available)
      # for it's version.
      # In some scenarios the results of the VirtualBox driver and the
      # additions installed on the host may differ. If this happens, we
      # assume, that the host binaries are right and yield a warning message.
      #
      # @return [String] The version code of the VirtualBox Guest Additions
      #                  available on the guest, or `nil` if none installed.
      def guest_version(reload = false)
        return @guest_version if @guest_version && !reload
        driver_version = super.to_s[/^(\d+\.\d+.\d+)/, 1]

        communicate.sudo('VBoxService --version', :error_check => false) do |type, data|
          service_version = data.to_s[/^(\d+\.\d+.\d+)/, 1]
          if service_version
            if driver_version != service_version
              @env.ui.warn(I18n.t("vagrant_vbguest.guest_version_reports_differ", :driver => driver_version, :service => service_version))
            end
            @guest_version = service_version
          end
        end
        @guest_version
      end

      # @param opts [Hash] Optional options Hash wich meight get passed to {Vagrant::Communication::SSH#execute} and firends
      # @yield [type, data] Takes a Block like {Vagrant::Communication::Base#execute} for realtime output of the command being executed
      # @yieldparam [String] type Type of the output, `:stdout`, `:stderr`, etc.
      # @yieldparam [String] data Data for the given output.
      def rebuild(opts=nil, &block)
        communicate.sudo("#{vboxadd_tool} setup", opts, &block)
      end

      # @param opts [Hash] Optional options Hash wich meight get passed to {Vagrant::Communication::SSH#execute} and firends
      # @yield [type, data] Takes a Block like {Vagrant::Communication::Base#execute} for realtime output of the command being executed
      # @yieldparam [String] type Type of the output, `:stdout`, `:stderr`, etc.
      # @yieldparam [String] data Data for the given output.
      def start(opts=nil, &block)
        opts = {:error_check => false}.merge(opts || {})
        if systemd_tool
          communicate.sudo("#{systemd_tool[:path]} vboxadd #{systemd_tool[:up]}", opts, &block)
        else
          communicate.sudo("#{vboxadd_tool} start", opts, &block)
        end
      end

      # Check for the presence of 'systemd' chkconfg or service command.
      #
      #    systemd_tool # => {:path=>"/usr/sbin/service", :up=>"start"}
      #
      # @return [Hash|nil] Hash with an absolute +path+ to the tool and the
      #                    command string for starting.
      #                    +nil* if neither was found.
      def systemd_tool
        return nil if @systemd_tool == false

        result = nil
        communicate.sudo('(which chkconfg || which service) 2>/dev/null', {:error_check => false}) do |type, data|
          path = data.to_s.strip
          case path
          when /\bservice\b/
            result = { path: path, up: "start", down: "stop" }
          when /\bchkconfg\b/
            result = { path: path, up: "on", down: "off" }
          end
        end

        if result.nil?
          @systemd_tool = false
          nil
        else
          @systemd_tool = result
        end
      end

      # Checks for the correct location of the 'vboxadd' tool.
      # It checks for a given list of possible locations. This list got
      # extracted from the 'VBoxLinuxAdditions.run' script.
      #
      # @return [String|nil] Absolute path to the +vboxadd+ tool,
      #                      or +nil+ if none found.
      def vboxadd_tool
        candidates = [
          "$Env:SystemRoot\\System32\\VBoxService.exe",
          "$Env:ProgramFiles\\Oracle\\VirtualBox Guest Additions",
          "${Env:ProgramFiles(x86)}\\Oracle\\VirtualBox Guest Additions"
          "/usr/lib/i386-linux-gnu/VBoxGuestAdditions/vboxadd",
          "/usr/lib/x86_64-linux-gnu/VBoxGuestAdditions/vboxadd",
          "/usr/lib64/VBoxGuestAdditions/vboxadd",
          "/usr/lib/VBoxGuestAdditions/vboxadd",
          "/lib64/VBoxGuestAdditions/vboxadd",
          "/lib/VBoxGuestAdditions/vboxadd",
          "/etc/init.d/vboxadd",
        ]
        cmd = <<-SHELL
        for c in #{candidates.join(" ")}; do
          if test -x "$c"; then
            echo $c
            break
          fi
        done
        SHELL

        path = nil
        communicate.sudo(cmd, {:error_check => false}) do |type, data|
          path = data.strip unless data.empty?
        end
        path
      end

      # A generic helper method to execute the installer.
      # This also yields a installation warning to the user, and an error
      # warning in the event that the installer returns a non-zero exit status.
      #
      # @param opts [Hash] Optional options Hash wich meight get passed to {Vagrant::Communication::SSH#execute} and firends
      # @yield [type, data] Takes a Block like {Vagrant::Communication::Base#execute} for realtime output of the command being executed
      # @yieldparam [String] type Type of the output, `:stdout`, `:stderr`, etc.
      # @yieldparam [String] data Data for the given output.
      def execute_installer(opts=nil, &block)
        yield_installation_waring(installer)
        opts = {:error_check => false}.merge(opts || {})
        exit_status = communicate.sudo("#{installer} #{installer_arguments}", opts, &block)
        yield_installation_error_warning(installer) unless exit_status == 0
        exit_status
      end

      # The absolute path to the GuestAdditions installer script.
      # The iso file has to be mounted on +mount_point+.
      def installer
        @installer ||= File.join(mount_point, 'VBoxWindowsAdditions.exe')
      end

      # The arguments string, which gets passed to the installer script
      def installer_arguments
        @installer_arguments ||= Array(options[:installer_arguments]).join " "
      end

      # A generic helper method for mounting the GuestAdditions iso file
      # on Windows systems with native PowerShell 4 or newer.
      # Mounts the given uploaded file from +tmp_path+ on +mount_point+.
      #
      # @param opts [Hash] Optional options Hash wich meight get passed to {Vagrant::Communication::SSH#execute} and firends
      # @yield [type, data] Takes a Block like {Vagrant::Communication::Base#execute} for realtime output of the command being executed
      # @yieldparam [String] type Type of the output, `:stdout`, `:stderr`, etc.
      # @yieldparam [String] data Data for the given output.
      def mount_iso(opts=nil, &block)
        cmd = <<-SHELL
        $CimInstance = Mount-DiskImage -ImagePath '#{tmp_path}' -PassThru
        $DriveLetter = $CimInstance | Get-Volume | Select-Object -Expand DriveLetter
        Write-Output "$($DriveLetter):\\"
        SHELL
        communicate.sudo(cmd, opts, &block) do |type, data|
          mount_point = data.strip unless data.empty?
        end
      end

      # A generic helper method for un-mounting the GuestAdditions iso file
      # on Windows systems with native PowerShell 4 or newer.
      # Unmounts the +tmp_path+.
      #
      # @param opts [Hash] Optional options Hash wich meight get passed to {Vagrant::Communication::SSH#execute} and firends
      # @yield [type, data] Takes a Block like {Vagrant::Communication::Base#execute} for realtime output of the command being executed
      # @yieldparam [String] type Type of the output, `:stdout`, `:stderr`, etc.
      # @yieldparam [String] data Data for the given output.
      def unmount_iso(opts=nil, &block)
        communicate.sudo("Dismount-DiskImage -ImagePath '#{tmp_path}'", opts, &block)
      end
    end
  end
end
VagrantVbguest::Installer.register(VagrantVbguest::Installers::Windows, 2)
