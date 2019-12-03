package ca.sfu.cmpt745.ex06.kittens;

/**
 * A bare bones API for modeling interactions with a kitten. You may imagine
 * that the API is implemented to make the kitten as terrifying as possible
 * if the API is misused. Much like real kittens, the API is poorly documented,
 * and developers may tread on dangerous ground by interacting with a kitten
 * in the wrong way at the wrong time.
 */
public final class Kitten1 {
  public static void main(String[] args) {
 	  Kitten k = new Kitten();
	  Kitten k1 = new Kitten();
 	  k.scare();
	  k.pet();
	  k1.feed();
  }
}

