#!/usr/bin/env ruby

# Copyright 2022 hidenory
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

require_relative "TaskManager"
require_relative "FileUtil"
require_relative "StrUtil"
require_relative "ExecUtil"
require 'optparse'
require "fileutils"
require 'shellwords'

class AnalyzeUtil
	def self.getListOfFilenameAndPath(paths)
		result = {}

		paths.each do |aPath|
			result[ FileUtil.getFilenameFromPath(aPath) ] = aPath
		end

		return result
	end

	def self.getAnalysisMissingNew(old_files, new_files)
		missingFiles = []
		newFiles = []
		commonFiles = []
		new_files.each do |k,v|
			if !old_files.has_key?(k)
				newFiles << k
			else
				commonFiles << {:targetFile=>k, :oldPath=>old_files[k], :newPath=>v}
			end
		end

		old_files.each do |k,v|
			missingFiles << k if !new_files.has_key?(k)
		end

		return commonFiles, missingFiles, newFiles
	end
end

class AndroidUtil
	DEF_DEX2JAR = ENV["PATH_DEX2JAR"] ? ENV["PATH_DEX2JAR"] : "d2j-dex2jar.sh"

	def self.isAndroidDex(jarPath)
		exec_cmd = "unzip -l #{Shellwords.escape(jarPath)} | grep \"\.dex$\""

		result = ExecUtil.getExecResultEachLine(exec_cmd)

		return result.to_a.length ? true : false
	end

	def self.extractArchive(archivePath, outputDir, specificFile=nil)
		exec_cmd = "unzip -o -qq  #{Shellwords.escape(archivePath)}"
		exec_cmd = "#{exec_cmd} #{Shellwords.escape(specificFile)}" if specificFile
		exec_cmd = "#{exec_cmd} -d #{Shellwords.escape(outputDir)} 2>/dev/null"

		ExecUtil.execCmd(exec_cmd)
	end

	def self.convertDex2Jar(dexPath, outputJarDir)
		filename = FileUtil.getFilenameFromPath(dexPath)
		pos = filename.to_s.rindex(".dex")
		filename = filename.to_s.slice(0, pos) if pos
		outputJarPath = "#{outputJarDir}/#{filename}.jar"

		exec_cmd = "#{Shellwords.escape(DEF_DEX2JAR)} #{Shellwords.escape(dexPath)} -o #{Shellwords.escape(outputJarPath)} --force"

		ExecUtil.execCmd(exec_cmd, outputJarDir)

		return outputJarPath
	end

	def self.mergeArchives(archivePaths, outputArchivePath, tempPath)
		tmpPath = "#{tempPath}/_tmp"
		archivePaths.each do |aPath|
			extractArchive(aPath, tmpPath)
		end
		exec_cmd = "zip -r -o -q #{Shellwords.escape(outputArchivePath)} *"
		ExecUtil.execCmd(exec_cmd, tmpPath)
	end

	DEF_DEPLOY_BASE_PATH = [
		"system/",
		"system_ext/",
		"product/",
		"oem/",
		"vendor/",
		"odm/",
		"apex/"
	]

	def self.isTargetAndroidBuiltOut(jarPath)
		result = false

		DEF_DEPLOY_BASE_PATH.each do | aDeployBasePath |
			result = jarPath.include?( aDeployBasePath )
			break if result
		end

		return result
	end

	def self.getListOfAndroidBuiltOutOnly(jarPaths)
		result = {}

		jarPaths.to_h.each do |jarName, aPath|
			result[ FileUtil.getFilenameFromPath(aPath) ] = aPath if isTargetAndroidBuiltOut(aPath)
		end

		return result
	end
end


class APICheckExecutor < TaskAsync
	def initialize(jarName, oldPath, newPath, oldImage, newImage, options, resultCallback)
		super("APICheckExecutor #{jarName}")
		@jarName = jarName
		@oldPath = oldPath
		@newPath = newPath
		@oldImage = oldImage
		@newImage = newImage
		@tempDirectory = options[:tempDirectory]
		@verbose = options[:verbose]
		@outputDirectory = options[:outputDirectory]
		@reportBase = options[:reportBase]
		@resultCallback = resultCallback
	end

	SZ_BIN_COMPAT 	= "Binary compatibility: "
	SZ_SRC_COMPAT 	= "Source compatibility: "
	SZ_BIN_COMPAT2	= "Total binary compatibility problems: "
	SZ_SRC_COMPAT2	= "Total source compatibility problems: "
	SZ_WARNINGS		= ", warnings: "

	def parseResult(result, aLine)
		if aLine.start_with?(SZ_BIN_COMPAT) then
			result[:binCompatibility] = aLine.slice(SZ_BIN_COMPAT.length, aLine.length-SZ_BIN_COMPAT.length-1).to_i

		elsif aLine.start_with?(SZ_SRC_COMPAT) then
			result[:srcCompatibility] = aLine.slice(SZ_SRC_COMPAT.length, aLine.length-SZ_SRC_COMPAT.length-1).to_i

		elsif aLine.start_with?(SZ_BIN_COMPAT2) then
			pos = aLine.index(",", SZ_BIN_COMPAT2.length)
			pos2 = aLine.index(SZ_WARNINGS, SZ_BIN_COMPAT2.length)
			if pos && pos2 then
				result[:binProblem] = aLine.slice(SZ_BIN_COMPAT2.length, aLine.length-pos).to_i
				result[:binWarning] = aLine.slice(pos2, aLine.length-pos2).to_i
			end

		elsif aLine.start_with?(SZ_SRC_COMPAT2) then
			pos = aLine.index(",", SZ_SRC_COMPAT2.length)
			pos2 = aLine.index(SZ_WARNINGS, SZ_SRC_COMPAT2.length)
			if pos && pos2 then
				result[:srcProblem] = aLine.slice(SZ_SRC_COMPAT2.length, aLine.length-pos).to_i
				result[:srcWarning] = aLine.slice(pos2, aLine.length-pos2).to_i
			end
		end
	end

	def _getTempPath(jarPath, prefixDir)
		filename = FileUtil.getFilenameFromPath(jarPath)
		pos = filename.to_s.rindex(".jar")
		filename = filename.to_s.slice(0, pos) if pos

		return "#{@tempDirectory}/#{filename}/#{prefixDir}"
	end

	def _convertAndroidDexToJavaIfNecessary(jarPath, prefixDir)
		jarFiles = []
		if AndroidUtil.isAndroidDex(jarPath) then
			tempDir = _getTempPath(jarPath, prefixDir)
			FileUtil.ensureDirectory(tempDir)
			AndroidUtil.extractArchive(jarPath, tempDir, "*.dex")
			dexJarFiles = FileUtil.getRegExpFilteredFiles(tempDir, "\.dex")
			dexJarFiles.each do |aDexJarFile|
				jarFiles << AndroidUtil.convertDex2Jar(aDexJarFile, tempDir)
			end
			jarFiles.sort!
			# multiple dex-jar files needs to convert bcause .dex file has 32767 symbol count issue
			if jarFiles.length>=2 then
				newJarPath = "#{tempDir}/#{FileUtil.getFilenameFromPath(jarPath)}"
				AndroidUtil.mergeArchives(jarFiles, newJarPath, tempDir)
				jarFiles = [newJarPath]
			end
		end

		return jarFiles.length ? jarFiles[0] : jarPath
	end

	def convertAndroidDexToJavaIfNecessary
		@oldPath = _convertAndroidDexToJavaIfNecessary(@oldPath, "old")
		@newPath = _convertAndroidDexToJavaIfNecessary(@newPath, "new")
	end

	def execute
		result = {
			:jarName=>@jarName,
			:binCompatibility=>0, 
			:srcCompatibility=>0, 
			:binProblem=>0, 
			:binWarning=>0, 
			:srcProblem=>0, 
			:srcWarning=>0,
			:report=>""
		}

		convertAndroidDexToJavaIfNecessary()

		exec_cmd = "japi-compliance-checker"
		exec_cmd = "#{exec_cmd} -old #{Shellwords.escape(@oldPath)} -new #{Shellwords.escape(@newPath)}"
		exec_cmd = "#{exec_cmd} -lib #{Shellwords.escape(@jarName)}"
		exec_cmd = "#{exec_cmd} -v1 #{@oldImage} -v2 #{@newImage}"
		exec_cmd = "#{exec_cmd} 2>/dev/null"

		IO.popen(exec_cmd, "r", :chdir=>@outputDirectory) {|io|
			while !io.eof? do
				aLine = StrUtil.ensureUtf8(io.readline.to_s.strip!)
				puts aLine if @verbose
				parseResult(result, aLine)
			end
			io.close()
		}
		result[:report] = "#{@reportBase ? @reportBase : @outputDirectory}/compat_reports/#{@jarName}/#{@oldImage}_to_#{@newImage}/compat_report.html"

		if ( @resultCallback!=nil ) then
			@resultCallback.call(result) #global callback
		end

		_doneTask()
	end
end

$g_criticalSection = Mutex.new
$g_result =[]
def addResult(result)
	$g_criticalSection.synchronize {
		$g_result << result
	}
end

class Reporter
	def self.convertArray(data, key)
		result = []
		data.each do |aData|
			result << {key=>aData}
		end
		return result
	end

	def self.titleOut(title)
		puts title
	end

	def self.report(data)
		if data.length then
			keys = data[0]
			if keys.kind_of?(Hash) then
				_conv(keys, true, false, true)
			end

			data.each do |aData|
				_conv(aData)
			end
		end
	end

	def self._conv(aData, keyOutput=false, valOutput=true, firstLine=false)
		puts aData
	end
end

class MarkdownReporter < Reporter
	def self.titleOut(title)
		puts "\# #{title}"
		puts ""
	end

	def self.reportFilter(aLine)
		if aLine.is_a?(String) then
			aLine = "[#{FileUtil.getFilenameFromPath(aLine)}](#{aLine})" if aLine.start_with?("http://")
		end

		return aLine
	end

	def self._conv(aData, keyOutput=false, valOutput=true, firstLine=false)
		separator = "|"
		aLine = separator
		count = 0
		if aData.kind_of?(Enumerable) then
			if aData.kind_of?(Hash) then
				aData.each do |aKey,theVal|
					aLine = "#{aLine} #{aKey} #{separator}" if keyOutput
					aLine = "#{aLine} #{reportFilter(theVal)} #{separator}" if valOutput
					count = count + 1
				end
			elsif aData.kind_of?(Array) then
				aData.each do |theVal|
					aLine = "#{aLine} #{reportFilter(theVal)} #{separator}" if valOutput
					count = count + 1
				end
			end
			puts aLine
			if firstLine && count then
				aLine = "|"
				for i in 1..count do
					aLine = "#{aLine} :--- |"
				end
				puts aLine
			end
		else
			puts "#{separator} #{reportFilter(aData)} #{separator}"
		end
	end
end

class CsvReporter < Reporter
	def self.titleOut(title)
		puts ""
	end

	def self._conv(aData, keyOutput=false, valOutput=true, firstLine=false)
		aLine = ""
		if aData.kind_of?(Enumerable) then
			if aData.kind_of?(Hash) then
				aData.each do |aKey,theVal|
					aLine = "#{aLine!="" ? "#{aLine}," : ""}#{aKey}" if keyOutput
					aLine = "#{aLine!="" ? "#{aLine}," : ""}#{theVal}" if valOutput
				end
			elsif aData.kind_of?(Array) then
				aData.each do |theVal|
					aLine = "#{aLine!="" ? "#{aLine}," : ""}#{theVal}" if valOutput
				end
			end
			puts aLine
		else
			puts "#{aData}"
		end
	end
end


#---- main --------------------------
options = {
	:verbose => false,
	:androidBuiltOutMode => false,
	:outputDirectory => ".",
	:reportBase => nil,
	:outputSections => "missing|new|problem|compatible",
	:dontReportIfNoIssue => false,
	:tempDirectory => "temp",
	:cleanupTemporary => true,
	:numOfThreads => TaskManagerAsync.getNumberOfProcessor()
}

reporter = MarkdownReporter

opt_parser = OptionParser.new do |opts|
	opts.banner = "Usage: usage <directory of old jar> <directory of new jar>"

	opts.on("-j", "--numOfThreads=", "Specify number of threads (default:#{options[:numOfThreads]})") do |numOfThreads|
		options[:numOfThreads] = numOfThreads.to_i
		options[:numOfThreads] = 1 if !options[:numOfThreads]
	end

	opts.on("-a", "--androidBuiltOutMode", "Specify if run as Android Built Out mode (default:#{options[:androidBuiltOutMode]})") do
		options[:androidBuiltOutMode] = true
	end

	opts.on("-o", "--outputDir=", "Specify compat_reports output directory (default:#{options[:outputDirectory]})") do |outputDirectory|
		options[:outputDirectory] = outputDirectory
	end

	opts.on("-t", "--temp=", "Specify temporary directory (default:#{options[:tempDirectory]})") do |tempDirectory|
		options[:tempDirectory] = tempDirectory
	end

	opts.on("-u", "--reportBase=", "Specify compat_reports base URL (default:#{options[:reportBase]})") do |reportBase|
		options[:reportBase] = reportBase
	end

	opts.on("-r", "--reportFormat=", "Specify report format markdown|csv|ruby (default:markdown)") do |reportFormat|
		case reportFormat.to_s.downcase
		when "ruby"
			reporter = Reporter
		when "csv"
			reporter = CsvReporter
		end
	end

	opts.on("-s", "--outputSections=", "Specify output sections (default:#{options[:outputSections]})") do |outputSections|
		options[:outputSections] = outputSections.to_s
	end

	opts.on("-d", "--dontReportIfNoIssue", "Specify to stop reporting if no issue found") do
		options[:dontReportIfNoIssue] = true
	end

	opts.on("-v", "--verbose", "Enable verbose status output") do
		options[:verbose] = true
	end

	opts.on("-k", "--keep-converted-jars", "Keep converted jars") do
		options[:cleanupTemporary] = false
	end
end.parse!

if (ARGV.length < 2) then
	puts opt_parser
	exit(-1)
else
	# check path
	for i in 0..1 do
		if ( !FileTest.directory?(ARGV[i]) ) then
			puts ARGV[i] + " is not found"
			exit(-1)
		end
	end
end

old_file_dir = FileUtil.getFilenameFromPath2(ARGV[0],2)
new_file_dir = FileUtil.getFilenameFromPath2(ARGV[1],2)

old_files = AnalyzeUtil.getListOfFilenameAndPath( FileUtil.getRegExpFilteredFiles(ARGV[0], "\.jar$") )
new_files = AnalyzeUtil.getListOfFilenameAndPath( FileUtil.getRegExpFilteredFiles(ARGV[1], "\.jar$") )

if options[:androidBuiltOutMode] then
	old_files = AndroidUtil.getListOfAndroidBuiltOutOnly( old_files )
	new_files = AndroidUtil.getListOfAndroidBuiltOutOnly( new_files )
end

commonFiles, missingFiles, newFiles = AnalyzeUtil.getAnalysisMissingNew(old_files, new_files)

if options[:outputSections].include?("missing") then
	enableHere = (options[:dontReportIfNoIssue] && !missingFiles.empty?) || !options[:dontReportIfNoIssue]
	reporter.titleOut("missing files") if enableHere
	if !missingFiles.empty? then
		reporter.report(Reporter.convertArray(missingFiles, "jarName"))
	else
		puts "nothing" if enableHere
	end
	puts "" if enableHere
end

if options[:outputSections].include?("new") then
	enableHere = (options[:dontReportIfNoIssue] && !newFiles.empty?) || !options[:dontReportIfNoIssue]
	reporter.titleOut("new files") if enableHere
	if !newFiles.empty?
		reporter.report(Reporter.convertArray(newFiles, "jarName"))
	else
		puts "nothing" if enableHere
	end
	puts "" if enableHere
end


result = []
taskMan = TaskManagerAsync.new( options[:numOfThreads].to_i )
commonFiles.each do |aJarFile|
	taskMan.addTask( APICheckExecutor.new(
		aJarFile[:targetFile], 
		aJarFile[:oldPath], 
		aJarFile[:newPath], 
		old_file_dir,
		new_file_dir,
		options,
		method(:addResult)
		)
	)
end
taskMan.executeAll()
taskMan.finalize()

compatibleJars = []
problematicJars = []
$g_result.sort_by! {|anItem| anItem[:jarName].to_s.downcase }
$g_result.each do |aResult|
	if aResult[:binCompatibility]!=100 ||
		aResult[:srcCompatibility]!=100 ||
		aResult[:binProblem]!=0 ||
		aResult[:binWarning]!=0 ||
		aResult[:srcProblem]!=0 ||
		aResult[:srcWarning]!=0
	then
		problematicJars << aResult
	else
		compatibleJars << aResult
	end
end

if options[:outputSections].include?("problem") then
	enableHere = (options[:dontReportIfNoIssue] && !problematicJars.empty?) || !options[:dontReportIfNoIssue]
	reporter.titleOut("Potential problematic Jars") if enableHere
	if !problematicJars.empty? then
		reporter.report(problematicJars)
	else
		puts "nothing" if enableHere
	end
	puts "" if enableHere
end

if options[:outputSections].include?("compatible") then
	if !options[:dontReportIfNoIssue] then
		reporter.titleOut("100% compatible Jars")
		if !compatibleJars.empty? then
			reporter.report(compatibleJars)
		else
			puts "nothing"
		end
	end
end

if options[:cleanupTemporary] then
	FileUtil.cleanupDirectory(options[:tempDirectory], true, true)
end