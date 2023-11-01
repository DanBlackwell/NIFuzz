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
 * Copyright 2013 Tom Chothia and Yusuke Kawamoto
 */
package bham.leakiest;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
//import java.util.Hashtable;
import java.util.Vector;

import bham.leakiest.infotheory.InfoTheory;
import bham.leakiest.infotheory.RandomSample;

/**
 * This class provides methods for dealing with continuous data.
 *
 * @author Tom Chothia
 * @author Yusuke Kawamoto
 * @version 1.4.9
 */
public class ContinuousData {
	/**
	 * List of data of each attribute
	 */
	public ArrayList<double[]> DataList = new ArrayList<double[]>();

	/**
	 * The number of shuffled samples
	 */
	public int testSize = TestInfoLeak.noOfTestsContinuous;

	/**
	 * Observation file name 1
	 */
	String obsFile1;

	/**
	 * Observation file name 2
	 */
	String obsFile2;

	private int verbose = 5;

	//private static String British = "./data/times/timesBritish1000";
	//private static String German = "./data/times/timesGerman500";
	//private static String Greek = "./data/times/timesGreek500Dist";
	//private static String Irish = "./data/times/timesIrish500";

	/**
	 * Constructs continuous data from two observation files.
	 * 
	 * @param dataFileName1 observation file name
	 * @param dataFileName2 observation file name
	 */
	public ContinuousData(String dataFileName1, String dataFileName2) {
		obsFile1 = dataFileName1;
		obsFile2 = dataFileName2;
	}

	/**
	 * Constructs the empty continuous data.
	 */
	public ContinuousData() {
		// Nothing to do here
	}

    /**
     * Sets a verbose.
     * @param v verbose
     */
    public void setVerbose(int v) {
    	this.verbose = v;
    }

    /**
     * Reads an observation (-o2 format) file.
     * 
     * @param fileName observation file name
     * @return array of observation data
     * @throws IOException Exception occurred when reading
     *         input from the observation file
     */
	public double[] loadData(String fileName) throws IOException {
		BufferedReader reader =  new BufferedReader(new FileReader(fileName));
		String line = reader.readLine();

		// Load the data into a Vector
		Vector<Double> fileData = new Vector<Double>();
		while(line != null) {
			fileData.add(Double.parseDouble(line));
			line = reader.readLine();
		}

		// Move the data into an array
		int Count = fileData.size();
		double[] Data = new double[Count];
		for(int i = 0; i < Count; i++) {
			Data[i] = fileData.get(i);
		}
		reader.close();
		return Data;
	}

    /**
     * Chooses half of observation data randomly,
     * shuffles them and return them as an array.
     * 
     * @param inputDist array of input distribution
     * @return array of shuffled observation data
     */
	public ArrayList<double[]> selectShuffled(double[] inputDist) {
		ArrayList<ArrayList<Double>> shuffledDataLists = new ArrayList<ArrayList<Double>>();
		// for each input value, create an initialised array list
		for(int x = 0; x < DataList.size(); x++) {
			ArrayList<Double> ald = new ArrayList<Double>();
			shuffledDataLists.add(ald);
		}
		//System.out.println("  inputDist.length = " + inputDist.length);
		if(inputDist.length != DataList.size()) {
			System.out.println("ERROR: The sizes of the input distribution and the data lists  are different:");
			System.out.println("  inputDist.length = " + inputDist.length);
			System.out.println("  DataList.size()  = " + DataList.size());
			System.exit(1);
		}
		
		// initialise random sapmling
		RandomSample rs = new RandomSample(inputDist);
		
		// for each input value
		for(int x = 0; x < DataList.size(); x++) {
			// for each data
			for(int j = 0; j < DataList.get(x).length; j++) {
				// randomly choose a secret value from inputDist and call it highValue
				int highValue = rs.indexOfValueDrawnFrom();
				// add (highValue, original observable) to the list
				shuffledDataLists.get(highValue).add( DataList.get(x)[j] );
				//System.out.println(" highValue: " + highValue + " DataList.get(x)[j]: " + DataList.get(x)[j]);
			}
		}
		
		// Convert the array lists into arrays
		ArrayList<double[]> result = new ArrayList<double[]>();
		for(int x = 0; x < DataList.size(); x++) {
			double[] data = new double[shuffledDataLists.get(x).size()];
			for(int j = 0; j < shuffledDataLists.get(x).size(); j++) {
				data[j] = shuffledDataLists.get(x).get(j);
			}
			result.add(data);
			/*
			if(result.get(x).length <= 0) {
				System.out.println("There are too many high values to calculate the confidence interval.");
				System.out.println("  (Failed to shuffle sub data.)");
				return null;
			}
			*/
		}
		return result;
	}

	/**
	 * Adds a fixed values to the Times2 so that
	 * their mean matches that of the Times1.
	 * This method is used only in the passport analyses.
	 * 
	 * @param Data1 array of data 1 (e.g. Times 1)
	 * @param Data2 array of data 1 (e.g. Times 2)
	 */
	public void fixedMeans(double[] Data1, double[] Data2) {
		// Calculate means
		double mean1 = InfoTheory.mean(Data1);
		double mean2 = InfoTheory.mean(Data2);
		
		if(mean1 - mean2 > 0) {
			double difference = mean1 - mean2;
			//System.out.println(" difference = " + difference);
			for(int i = 0; i < Data2.length; i++) {
				Data2[i] += difference;
			}
		} else {
			double difference = mean2 - mean1;
			//System.out.println(" difference = " + difference);
			for(int i = 0; i < Data1.length; i++) {
				Data1[i] += difference;
			}
		}
	}

	/**
	 * Adds a fixed values to the Times2 so that
	 * their median matches that of the Times1.
	 * This method is used only in the passport analyses.
	 * 
	 * @param Data1 array of data 1 (e.g. Times 1)
	 * @param Data2 array of data 1 (e.g. Times 2)
	 */
	public void fixedMedians(double[] Data1, double[] Data2) {
		// Calculate medians
		double median1 = InfoTheory.median(Data1);
		double median2 = InfoTheory.median(Data2);
		
		if(median1 - median2 > 0) {
			double difference = median1 - median2;
			//System.out.println(" difference = " + difference);
			for(int i = 0; i < Data2.length; i++) {
				Data2[i] += difference;
			}
		} else {
			double difference = median2 - median1;
			//System.out.println(" difference = " + difference);
			for(int i = 0; i < Data1.length; i++) {
				Data1[i] += difference;
			}
		}
	}

	/**
	 *  Print contents of cdata for debug.
	 */
	public void printData() {
		for(int i = 0; i < DataList.size(); i++) {
			System.out.println(" i = " + i);
			for(int j = 0; j < DataList.get(i).length; j++) {
				System.out.println(j + " " + DataList.get(i)[j]);
			}
			System.out.println("-----------");
		}
		
	}
	
	/*
	 * 
	 * @param data
	 * @param roundPlaces
	 * @return
	 */
	/*
	public Hashtable<Double, Integer> getCountHash(double[] data, int roundPlaces) {
		Hashtable<Double, Integer> countHash = new Hashtable<Double, Integer>();
		for(double valueLong : data) {
			double value = Stats.round(valueLong, roundPlaces);
			if(countHash.containsKey(value)) {
				countHash.put(value, countHash.get(value)+1);
			} else {
				countHash.put(value, 1);
			}
		}
		return countHash;
	}
	 */
}
