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
 * Copyright 2013 Tom Chothia, Yusuke Kawamoto and Chris Novakovic
 */
package bham.leakiest.infotheory;

import java.security.SecureRandom;
//import java.util.Collection;
//import java.io.*;
//import java.util.ArrayList;
//import java.util.HashSet;
//import java.util.HashMap;
import bham.leakiest.ProbDist;
//import bham.leakiest.State;
import bham.leakiest.TestInfoLeak;

/**
 * This class constructs a probability distribution and offers
 * methods for manipulating the probability distribution.
 * 
 * @author Tom Chothia
 * @author Yusuke Kawamoto
 * @author Chris Novakovic
 * @version 1.4.6
 */
public class RandomSample {
	private boolean forbid_overwrite;
	private final int NOT_FOUND = -1;
	private final int NAN = -1;
    private static int verbose = TestInfoLeak.verbose;
	protected static final double ERROR = -1;
	protected static final double accuracy = 0.0000000001;
	private double[] pmf;
	private double[] cdf;
	private SecureRandom random;
	
	/**
	 * Initialises the random sampling from a given array of probability distribution.
	 * 
	 * @param pmf_in array of PMF
	 */
	public RandomSample(double[] pmf_in) {
		pmf = new double[pmf_in.length];
		System.arraycopy(pmf_in,0,pmf,0,pmf_in.length);
		cdf = ProbDist.cumulativeProbArray(pmf);
		random = new SecureRandom(); // Generate a random seed
	}

	/**
	 * Initialises the random sampling from a given probability distribution.
	 * 
	 * @param pd probability distribution
	 */
	public RandomSample(ProbDist pd) {
		pmf = pd.getPMFArray();
		cdf = ProbDist.cumulativeProbArray(pmf);
		random = new SecureRandom(); // Generate a random seed
	}
	
	/**
	 * Draws and returns the index of a single value randomly from a given array of PMF.
	 * 
	 * @param  pmf array of PMF
	 * @return the index of a value randomly drawn from a given distribution
	 */
	public int indexOfValueDrawnFrom() {
		double randomProb = random.nextDouble();
		int i = 0;
		for(i = 0; i< cdf.length; i++) {
			if(cdf[i] >= randomProb) {
				return i;
			}
		}
		/*
		double sum = 0;
		do {
			sum += pmf[i];
			i++;
		} while(sum < randomProb && i < pmf.length);
		return i-1;
		*/
		return pmf.length-1;
	}
	
	/**
	 * Draws and returns a single value randomly from a given array of PMF.
	 * 
	 * @param  pmf array of PMF
	 * @return a value randomly drawn from a given distribution
	 */
	public double drawFrom() {
		int index = indexOfValueDrawnFrom();
		return pmf[index];
	}

}
