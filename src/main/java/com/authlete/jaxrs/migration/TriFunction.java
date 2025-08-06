package com.authlete.jaxrs.migration;

/**
 * A templated functional interface that takes three arguments and returns a single value.
 *
 * @param <T1> input type 1
 * @param <T2> input type 2
 * @param <T3> input type 3
 * @param <R> result type
 *
 * @author kylegonzalez
 */
@FunctionalInterface
public interface TriFunction<T1, T2, T3, R>
{
    R apply(T1 t1, T2 t2, T3 t3);
}
