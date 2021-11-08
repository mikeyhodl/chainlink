import {
  ApolloLink,
  ApolloClient,
  InMemoryCache,
  HttpLink,
} from '@apollo/client'
import { onError } from '@apollo/client/link/error'
import generatedIntrospection from 'src/types/generated/possibleTypes'

const httpLink = new HttpLink({
  uri: `${process.env.CHAINLINK_BASEURL}/query`,
  credentials: 'include',
})

// Log any GraphQL errors or network error that occurred.
//
// Hook into here to clear the user and redirect them back to the login page
const errorLink = onError(({ graphQLErrors, networkError }) => {
  if (graphQLErrors)
    graphQLErrors.forEach(({ message, locations, path }) =>
      console.log(
        `[GraphQL error]: Message: ${message}, Location: ${locations}, Path: ${path}`,
      ),
    )
  if (networkError) console.log(`[Network error]: ${networkError}`)
})

export const client = new ApolloClient({
  cache: new InMemoryCache({
    possibleTypes: generatedIntrospection.possibleTypes,
  }),
  link: ApolloLink.from([errorLink, httpLink]),
})
