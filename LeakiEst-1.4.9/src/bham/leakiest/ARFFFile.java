/*
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright 2014 Tom Chothia, Yusuke Kawamoto and Chris Novakovic
 */
package bham.leakiest;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * This file contains the methods needed to process ARFF files.
 * 
 * @author Tom Chothia
 * @author Yusuke Kawamoto
 * @author Chris Novakovic
 * @version 1.4.7
 */
public class ARFFFile {
	/**
	 * Array of attributes
	 */
	public String[] attributes;

	/**
	 * The number of samples
	 */
	public int noOfTests;

	private String relation;
	private String[] featureTypes;
	private String[][] samples;
	private String fileName;
	private int verbose;
	private int csvInterval;
    private CSVFile csvFile;
    private boolean terminateWhenStabilised = false;

	/**
	 * Opens an ARFF file for reading.
	 * @param fileName ARFF file name
	 * @param v verbose
	 */
	public ARFFFile(String fileName, int v) {
    	if(( fileName.startsWith("\"") || fileName.startsWith("\'") || fileName.startsWith("`") ) &&
    	   ( fileName.endsWith("\"") || fileName.endsWith("\'") || fileName.startsWith("`") ))
    		this.fileName = fileName.substring(1, fileName.length()-1);
    	else
    		this.fileName = fileName;
    	verbose = v;
    	this.readAndParse();
	}
	
	/**
	 * Opens an ARFF file for reading in increments of a given number of lines.
	 * @param fileName ARFF file name
	 * @param v Verbosity level
	 * @param csvInterval Number of lines to read from the file during each
     * increment
     * @param csvFile The CSV file to write intermediate leakage estimates to
	 */
	public ARFFFile(String fileName, int v, int csvInterval, CSVFile csvFile) {
    	if(( fileName.startsWith("\"") || fileName.startsWith("\'") || fileName.startsWith("`") ) &&
    	   ( fileName.endsWith("\"") || fileName.endsWith("\'") || fileName.startsWith("`") ))
    		this.fileName = fileName.substring(1, fileName.length()-1);
    	else
    		this.fileName = fileName;
    	verbose = v;
    	this.csvInterval = csvInterval;
    	this.csvFile = csvFile;
    	this.readAndParse();
	}
	
	/**
     * Controls whether the <tt>obsFromARFF()</tt> method should terminate
     * before it has finished reading all of the available samples, if the
     * corrected leakage value stabilises.
     * @param flag <tt>true</tt> to terminate early; <tt>false</tt> to read all
     * of the samples regardless.
     */
    public void setTerminateWhenStabilised(boolean flag) {
    	terminateWhenStabilised = flag;
    	if (flag && verbose > 3) System.out.println("Samples will stop being read when the corrected leakage value stabilises.");
    }

	/*
	 * Sets values from the ARFF file.
	 * 
	 * @param n Relation name of the ARFF file.
	 * @param attributeNames list of attribute names
	 * @param attributeTypes list of attribute types
	 * @param data list of data of each attribute
	 */
	private void setValues(String n, ArrayList<String> attributeNames,
						  ArrayList<String> attributeTypes, ArrayList<String[]> data) {
		this.relation = n;
		this.attributes = new String[attributeNames.size()];
		attributeNames.toArray(this.attributes); 
		this.featureTypes = new String[attributeTypes.size()];
		attributeTypes.toArray(this.featureTypes); 
		this.samples = new String[data.size()][attributes.length];
		data.toArray(samples);
	}


	/**
	 * Reads and parses the ARFF file.
	 */
	private void readAndParse() {
		//open file
		try {
			BufferedReader reader =  new BufferedReader(new FileReader(fileName));
	    	if(verbose > 3)
	    		System.out.println("Loading data (ARFF) from " + fileName + " ...");

			// Trim comments before @relation
			String line = nextNonBlankLine(reader);
			while(line != null) {
				if((line.trim()).startsWith("//") || (line.trim()).startsWith("%")) {
					line = nextNonBlankLine(reader);
		    		//System.out.println("  " + line);
				} else {
					break;
				}
			}

			//Find the file name
			Pattern pattern = Pattern.compile("@relation ([\\S]+)");	
			Matcher matcher = pattern.matcher(line);
			String name = null;
			if(matcher.find()) { 
				name = matcher.group(1).trim(); 
				//System.out.println("Relation name is:"+name+" From: "+line);
			} else {
				System.err.println("Badly formed ARFF file. Excepted this to be the relation name:"+line);
				System.exit(-1);
			}

			// Trim comments before @attribute
			while(line != null) {
				if((line.trim()).startsWith("%") || (line.trim()).startsWith("//")) {
					line = nextNonBlankLine(reader);
		    		//System.out.println("  " + line);
				} else {
					break;
				}
			}

			// Find the attributes
			line = nextNonBlankLine(reader);
			boolean parsingAttributes = true;
			ArrayList<String> attributeNames = new ArrayList<String>();
			ArrayList<String> attributeTypes = new ArrayList<String>();

			while(parsingAttributes) {
				pattern = Pattern.compile("@attribute ([\\S]+) ([\\S]+)");	
				matcher = pattern.matcher(line);
				if(matcher.find()) { 
					attributeNames.add(matcher.group(1).trim());
					attributeTypes.add(matcher.group(2).trim());
					line = nextNonBlankLine(reader);
				} else {
					parsingAttributes = false;
				}
			}
			
			// Parse Data
			line = nextNonBlankLine(reader);
			ArrayList<String[]> data = new ArrayList<String[]>();
			int lineCounter = 1;
			while(line != null) {
				if(!((line.trim()).equalsIgnoreCase("") || (line.trim()).startsWith("%") || (line.trim()).startsWith("//"))) {
					//String[] splitedLine = line.split(",| ");
					String[] splitedLine = splitLineByCommas(line);
					if(splitedLine.length == attributeNames.size()) {
						data.add(splitedLine);
					} else {
						System.out.println("File format error: there are " + splitedLine.length +
								           " attributes in line " + lineCounter + ":");
						System.out.println(line);
						System.exit(-1);
					}
				}
				line = reader.readLine();
				lineCounter++;
			}
			// Return the results as an ARFFfile
			setValues(name, attributeNames, attributeTypes, data);
		} catch(FileNotFoundException ex) {
		     System.out.println("File not found: " + fileName);
		     System.out.println("Failed to read ARFF file.");
		     System.exit(1);
		} catch(Exception ex) {
		     System.out.println("Error reading ARFF file " + fileName + ": " + ex);
			//ex.printStackTrace();
			System.exit(-1);
		}
	}

	/**
	 * Returns the samples array.
	 * 
	 * @return the samples array
	 */
	public String[][] getSamples(){
		return this.samples;
	}
	
	
	/*
	 * Skips blank lines when reading a file.
	 */
	private String nextNonBlankLine(BufferedReader reader) throws IOException {
		String line = reader.readLine();	
		while( (line.trim()).equalsIgnoreCase("") || (line.trim()).startsWith("//")) {
			line = reader.readLine();
		}
		return line;
	}

	
	/*
	 * This method is used in the method readAndParse.
	 */
	private String[] splitLineByCommas(String line) {
		//System.out.println(" line: " + line.trim() + "   " + lineCounter);
		//System.out.println(" len:  " + ch.length);
		char ch[] = line.trim().toCharArray();
		ArrayList<String> splitedLine = new ArrayList<String>();
		boolean insideQuote = false;
		String element = "";
		for(int i = 0; i < ch.length; i++) {
			if(ch[i] == '\\') {
				element = element + ch[i];
				i++;
				if(i < ch.length)	element = element + ch[i];
			} else if(ch[i] == '"') {
				insideQuote = !insideQuote;
			} else if(!insideQuote && ch[i] == ',') {
				splitedLine.add(element);
				element = "";
			} else if(!insideQuote && ch[i] == ' ') {
				splitedLine.add(element);
				element = "";
			} else {
				element = element + ch[i];
			}
		}
		splitedLine.add(element);
		/*
		System.out.print(" =====> ");
		for(String str : splitedLine) {
			System.out.print(str + "   ");
		}
		System.out.println();
		*/
		return (String[])splitedLine.toArray(new String[splitedLine.size()]);
	}


	/*
	 * This method is used in the method obsFromARFF.
	 */
	private String sprintPad0(String str, int md_i, int md_d) {
		try {
			double d = Double.parseDouble(str);
			int len_i = String.valueOf((int)d).length();
			int len_d = str.length() - len_i;
			if(str.indexOf(".") != -1)
				len_d--;
			//System.out.print("str " + str + "  len_i " + len_i + "  len_d " + len_d);
			String ret = "";
			for(int i = 0; i < md_i - len_i; i++)
				ret += "0";
			ret += str;
			for(int i = 0; i < md_d - len_d; i++)
				ret += "0";
			//System.out.println("  ret-str " + ret);
			return ret;
		} catch(Exception e) {
			return str;
		}
	}
	
	/*
	 * This method is used in the method obsFromARFF.
	 */
	private int maxDigitsInt(int j) {
		int maxlen = 0;
		try {
			for(int i = 0; i < samples.length; i++) {
				String sample = samples[i][j];
				//System.out.println("i " + i + "  j " + j);
				//System.out.println("len of " + sample);
				double d = Double.parseDouble(sample);
				int len = String.valueOf((int)d).length();
				maxlen = Math.max(maxlen, len);
				//System.out.println(" = " + len);
			}
			return maxlen;
		} catch(Exception e) {
			return maxlen;
		}
	}

	/*
	 * This method is used in the method obsFromARFF.
	 */
	private int maxDigits(int j) {
		int maxlen = 0;
		try {
			for(int i = 0; i < samples.length; i++) {
				String sample = samples[i][j];
				//System.out.print("i " + i + "  j " + j + "   ");
				//System.out.print("len of " + sample);
				//double d = Double.parseDouble(sample);
				int len = sample.length();
				if(sample.indexOf(".") != -1)
					len--;
				maxlen = Math.max(maxlen, len);
				//System.out.println(" = " + len);
			}
			return maxlen;
		} catch(Exception e) {
			return maxlen;
		}
	}

	/**
	 * Computes the observations from a given ARFF file and given features.
	 * 
	 * @param fileName name of an ARFF file
	 * @param highFeaturesSet set of strings representing high features
	 * @param lowFeaturesSet set of strings representing low features
	 * @return observations
	 */
    public static Observations computeObservationsFromARFF(String fileName, TreeSet<String> highFeaturesSet, TreeSet<String> lowFeaturesSet) {
		// Read the ARFF file and generate a channel matrix using the ReadFile Class
		ARFFFile file = new ARFFFile(fileName, 0);
		// Add high features specified by names
		TreeSet<Integer> highFeatures = new TreeSet<Integer>();
		highFeatures = file.getFeatureIndices(highFeatures, highFeaturesSet);
		// Add low features specified by names
		TreeSet<Integer> lowFeatures = new TreeSet<Integer>();
		lowFeatures = file.getFeatureIndices(lowFeatures, lowFeaturesSet);
		//Calculate the observations
		Observations obs = file.obsFromARFF(highFeatures, lowFeatures);
		return obs;
    }
	
	/**
	 * Returns the observation for specified high and low features.
	 * 
	 * @param inputIndexes tree set of high feature attribute indexes
	 * @param outputIndexes tree set of low feature attribute indexes
	 * @return observation
	 */
	public Observations obsFromARFF(TreeSet<Integer> inputIndexes, TreeSet<Integer> outputIndexes) {
		if(inputIndexes.size() < 1) {
    		System.out.println("Commandline option error: -high <numbers> is missing or badly specified");
			System.exit(1);
		}
		if(outputIndexes.size() < 1) {
    		System.out.println("Commandline option error: -low <numbers> is missing or badly specified");
			System.exit(1);
		}
		
		Observations obs = new Observations();
		
		double correctedLeakageFirstInterval = Double.NaN, correctedLeakageSecondInterval = Double.NaN;
		int nextLeakageInterval = TestInfoLeak.LEAKAGE_STABILISATION_INITIAL_INTERVAL;

		for (int i = 0; i < samples.length; i++) {
			String input = "";
	        for (int j : inputIndexes) {
	        	if (j < attributes.length) {
	        		int mdi = maxDigitsInt(j); // Check the maximum number of digits of integer for output indexes
	        		int mdd = maxDigits(j) - mdi; // Check the maximum number of decimal places for output indexes
	        		//System.out.println("j " + j + "  mdi " + mdi + "  mdd " + mdd);
	        		if (input.equalsIgnoreCase("")) {
	        			input = sprintPad0(samples[i][j], mdi, mdd);
	        		} else {
	        			input = input + "_" + sprintPad0(samples[i][j], mdi, mdd);
	        		}
	        	} else {
	        		System.out.println("Commandline option error: -low " + j);
	        		System.out.println("  " + j + " is greater than the number of attributes.");
	        		System.exit(1);
	        	}
	        }
	        if (verbose >= 5) System.out.println("input " + input);

			String output = "";
			for (int j : outputIndexes) {
				int mdi = maxDigitsInt(j); // Check the maximum number of digits of integer for output indexes
				int mdd = maxDigits(j) - mdi; // Check the maximum number of decimal places for output indexes
				//System.out.println("j " + j + "  mdi " + mdi + "  mdd " + mdd);
	        	if (output.equalsIgnoreCase("")) {
	        		output = sprintPad0(samples[i][j], mdi, mdd);
	        	} else {
	        		output = output + "_" + sprintPad0(samples[i][j], mdi, mdd);
	        	}
	        }
	        if (verbose >= 5) System.out.println("output " + output);

			obs.addObservation(input, output);
			
			// If we've now processed the number of ARFF lines necessary to do
			// an intermediate leakage calculation, do it now
			if (csvInterval != 0 && (i + 1) % csvInterval == 0) {
				csvFile.addLeakageData(obs, TestInfoLeak.taskType);
			}
			
			// If we're terminating after the leakage stabilises, and if
			// we've reached an interval where we need to check whether
			// the leakage has changed, check now
			if (terminateWhenStabilised && (i + 1) == nextLeakageInterval) {
				nextLeakageInterval += 2 * (obs.getUniqueInputCount() * obs.getUniqueOutputCount());
				
				// If we don't have a first corrected leakage value yet,
				// set it to be the current corrected leakage value and
				// set the second one after another 2i*2o samples have
				// been read
				if (Double.isNaN(correctedLeakageFirstInterval)) {
					correctedLeakageFirstInterval = Estimate.getCorrectedMutualInformation(obs);
					if (verbose > 3) System.out.printf("After %d samples: corrected leakage = %.4f bits; leakage differs by > %s, checking again after %d samples\n", (i + 1), correctedLeakageFirstInterval, String.valueOf(TestInfoLeak.LEAKAGE_STABILISATION_DELTA), nextLeakageInterval);
					
				// Otherwise, store the current corrected leakage value
				// as the second corrected leakage value and compare it
				// to the first -- if the leakage differs by more than
				// STABILISATION_DELTA then keep going and set another
				// interval for 2(i*o) samples' time; otherwise, stop
				} else {
					correctedLeakageSecondInterval = Estimate.getCorrectedMutualInformation(obs);
					
					if (Math.abs(correctedLeakageSecondInterval - correctedLeakageFirstInterval) <= TestInfoLeak.LEAKAGE_STABILISATION_DELTA) {
						if (verbose > 3) System.out.printf("After %d samples: corrected leakage = %.4f bits; leakage differs by <= %s, not reading any more samples\n", (i + 1), correctedLeakageSecondInterval, String.valueOf(TestInfoLeak.LEAKAGE_STABILISATION_DELTA));
						break;
					} else {
						if (verbose > 3) System.out.printf("After %d samples: corrected leakage = %.4f bits; leakage differs by > %s, checking again after %d samples\n", (i + 1), correctedLeakageSecondInterval, String.valueOf(TestInfoLeak.LEAKAGE_STABILISATION_DELTA), nextLeakageInterval);
						correctedLeakageFirstInterval = correctedLeakageSecondInterval;
					}
				}
			}
		}
		
		return obs;
	}

	/**
	 * Returns the continuous data for the given high and low features.
	 * 
	 * @param inputIndexes Tree set of high feature attribute indexes
	 * @param outputIndexes Tree set of low feature attribute indexes
	 * @param verbose verbose
	 * @return the continuous data for the given high and low features
	 */
	public ContinuousData cdataFromARFF(TreeSet<Integer> inputIndexes, TreeSet<Integer> outputIndexes, int verbose) {
		ContinuousData cdata = new ContinuousData();
		ArrayList<ArrayList<Double>> tmpDataList = new ArrayList<ArrayList<Double>>();
		int outputAttribute = outputIndexes.first();
		
		ArrayList<String> inputNames = new ArrayList<String>(); 
		for(int i = 0; i < samples.length; i++) {
			String input = "";
			Iterator<Integer> itin = inputIndexes.iterator();
	        while(itin.hasNext()) {
	        	int j = itin.next();
	        	if(j < attributes.length) {
	        		int mdi = maxDigitsInt(j); // Check the miximum number of digits of integer for output indexes
	        		int mdd = maxDigits(j) - mdi; // Check the miximum of dicimal places for output indexes
	        		//System.out.println("j " + j + "  mdi " + mdi + "  mdd " + mdd);
	        		if(input.equalsIgnoreCase(""))
	        			input = sprintPad0(samples[i][j], mdi, mdd);
	        		else
	        			input = input + "_" + sprintPad0(samples[i][j], mdi, mdd);
	        	} else {
	        		System.out.println("Commandline option error: -low " + j);
	        		System.out.println("  " + j + " is greater than the number of attributes.");
	        		System.exit(1);
	        	}
	        }
	        /*
	        if(verbose > 3)
	        	System.out.println("input " + input);
	        */
	        
			// Create the array of inputNames
			int inputIndex = 0;
			boolean foundInput = false;
			while(inputIndex < inputNames.size() && !foundInput) {
				if( ((String) inputNames.get(inputIndex)).equals(input) ) {
					foundInput = true;
					try {
						double output = Double.parseDouble(samples[i][outputAttribute]);
						if(Double.isNaN(output)) {
							System.out.println("Ignoared data: NaN (" + i + ", " + outputAttribute + ")");
						} else {
							tmpDataList.get(inputIndex).add(output);
							//System.out.println("samples[" + i + "][outputAttribute]: " + samples[i][outputAttribute]);
							/*
							if(verbose > 3)
								System.out.println("output " + output);
						    */
						}
					} catch(Exception e) {
						if(verbose > 3)
							System.out.println("Error in parsing data: " + e);
						return null;
					}
				} else {
					inputIndex++;
				}
			}
			if(!foundInput) {
				inputNames.add(input);
				try {
					ArrayList<Double> list = new ArrayList<Double>();
					list.add(Double.parseDouble(samples[i][outputAttribute]));
					//System.out.println("outputAttribute: " + outputAttribute);
					tmpDataList.add(list);
				} catch(Exception e) {
					if(verbose > 3)
						System.out.println("Error in parsing data: " + e);
					if(verbose > 1)
						System.out.println("The specified feature may not be continuous.");
					return null;
				}
			}
			noOfTests++;
		}

		// Convert the array lists to arrays
		for(ArrayList<Double> ald : tmpDataList) {
			double[] tmp = new double[ald.size()];
			for(int i = 0; i < ald.size(); i++) {
				tmp[i] = ald.get(i);
			}
			cdata.DataList.add(tmp);
		}
		return cdata;
	}

	//////////////////////////////////////////
	////// Functions for feature indices /////
	/**
	 * Computes the a tree set of feature indices that appear in
	 * the given string set.
	 * 
	 * @param features tree set of integers each representing a selected feature
	 * @param featuresSet tree set of strings each representing a selected feature
	 * @return feature indices
	 */
	public TreeSet<Integer> getFeatureIndices(TreeSet<Integer> features, TreeSet<String> featuresSet) {
		for(String fs : featuresSet) {
			for(int a = 0; a < this.attributes.length; a++) {
				if(fs.equals(this.attributes[a]))
					features.add(a);
			}
		}
		return features;
	}
	
	/**
	 * Returns the string representing the low features.
	 * 
	 * @param lowFeatures the set of indeces representing low features
	 * @param verbose verbose
	 * @return the string representing the low features
	 */
	protected String getStringLowFeatures(TreeSet<Integer> lowFeatures, int verbose) {
		// String representing the low features
		String str = "";
		Iterator<Integer> itl = lowFeatures.iterator();
		while(itl.hasNext()) {
			int atr = itl.next();
			if(atr >= this.attributes.length) { //specified value atr is too big
				lowFeatures.remove(atr);
				System.out.println(" Ignored commandline option: -low " + atr);
				System.out.println(" There is no attribute for number " + atr + "." );
			} else {
				str += "  " + String.format("%d ", atr) + this.attributes[atr];
				if(verbose > 1)
					System.out.println(" " + atr + " " + this.attributes[atr]);
			}
		}
		return str;
	}

	
	//////////////////////////////////////////
	////// Print functions               /////
	/**
	 * Print the features that are selected to be investigated.
	 * 
	 * @param highFeatures the set of indeces representing high features
	 * @param lowFeatures the set of indeces representing low features
	 * @param verbose verbose
	 */
	public void printFeatures(TreeSet<Integer> highFeatures, TreeSet<Integer> lowFeatures, int verbose) {
		// Print high features
		if(verbose > 1)
			System.out.println("High features: ");
		Iterator<Integer> ith = highFeatures.iterator();
		while(ith.hasNext()) {
			int atr = ith.next();
			if(atr >= this.attributes.length) { //specified value atr is too big
				highFeatures.remove(atr);
				System.out.println(" Ignored commandline option: -high " + atr);
				System.out.println("Error: There is no attribute for number " + atr + "." );
				System.exit(1);
			} else if(verbose > 1)
				System.out.println(" " + atr + " " + this.attributes[atr]);
		}

		// Print low features
		if(verbose > 1)
			System.out.println("Low features:  ");
		Iterator<Integer> itl = lowFeatures.iterator();
		while(itl.hasNext()) {
			int atr = itl.next();
			if(atr >= this.attributes.length) { //specified value atr is too big
				lowFeatures.remove(atr);
				System.out.println(" Ignored commandline option: -low " + atr);
				System.out.println(" There is no attribute for number " + atr + "." );
			} else {
				if(verbose > 1)
					System.out.println(" " + atr + " " + this.attributes[atr]);
			}
		}
		if(verbose > 1)
			System.out.println();
	}
	

}
