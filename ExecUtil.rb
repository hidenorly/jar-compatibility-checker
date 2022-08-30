#  Copyright (C) 2022 hidenorly
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

require "./StrUtil"
require 'timeout'

class ExecUtil
	def self.execCmd(command, execPath=".", quiet=true)
		if File.directory?(execPath) then
			exec_cmd = command
			exec_cmd += " > /dev/null 2>&1" if quiet && !exec_cmd.include?("> /dev/null")
			system(exec_cmd, :chdir=>execPath)
		end
	end

	def self.hasResult?(command, execPath=".", enableStderr=true)
		result = false

		if File.directory?(execPath) then
			exec_cmd = command
			exec_cmd += " 2>&1" if enableStderr && !exec_cmd.include?(" 2>")

			IO.popen(exec_cmd, "r", :chdir=>execPath) {|io|
				while !io.eof? do
					if io.readline then
						result = true
						break
					end
				end
				io.close()
			}
		end

		return result
	end

	def self.getExecResultEachLine(command, execPath=".", enableStderr=true, enableStrip=true, enableMultiLine=true)
		result = []

		if File.directory?(execPath) then
			exec_cmd = command
			exec_cmd += " 2>&1" if enableStderr && !exec_cmd.include?(" 2>")

			IO.popen(exec_cmd, "r", :chdir=>execPath) {|io|
				while !io.eof? do
					aLine = StrUtil.ensureUtf8(io.readline)
					aLine.strip! if enableStrip
					result << aLine
				end
				io.close()
			}
		end

		return result
	end

	def self.getExecResultEachLineWithTimeout(exec_cmd, execPath=".", timeOutSec=3600, enableStderr=true, enableStrip=true)
		result = []
		pio = nil
		begin
			Timeout.timeout(timeOutSec) do
				if File.directory?(execPath) then
					if enableStderr then
						pio = IO.popen(exec_cmd, STDERR=>[:child, STDOUT], :chdir=>execPath )
					else
						pio = IO.popen(exec_cmd, :chdir=>execPath )
					end
					if pio && !pio.eof?then
						aLine = StrUtil.ensureUtf8(pio.read)
						result = aLine.split("\n")
						if enableStrip then
							result.each do |aLine|
								aLine.strip!
							end
						end
					end
				end
			end
		rescue Timeout::Error => ex
#			puts "timeout error"
			if pio then
				if !pio.closed? && pio.pid then
					Process.detach(pio.pid)
					Process.kill(9, pio.pid)
				end
			end
		rescue
#			puts "Error on execution : #{exec_cmd}"
			# do nothing
		ensure
			pio.close if pio && !pio.closed?
			pio = nil
		end

		return result
	end
end
