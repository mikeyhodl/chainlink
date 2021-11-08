import * as React from 'react'

import { ApolloError } from '@apollo/client'
import { GraphQLError } from 'graphql'
import { render, renderWithRouter, screen } from 'support/test-utils'

import { ErrorHandler } from './ErrorHandler'
import { Route } from 'react-router'

const { findByText, queryByText } = screen

it('renders nothing when error is nil', async () => {
  render(<ErrorHandler />)

  expect(expect(document.documentElement).toHaveTextContent(''))
})

it('renders the error', async () => {
  const graphQLErrors = [new GraphQLError('Something went wrong with GraphQL')]
  const errorMessage = 'this is an error message'
  const apolloError = new ApolloError({
    graphQLErrors,
    errorMessage,
  })

  render(<ErrorHandler error={apolloError} />)

  expect(queryByText('Error: this is an error message')).toBeInTheDocument()
})

it('redirects when the error is unauthorized', async () => {
  const graphQLErrors = [
    new GraphQLError(
      'Unauthorized',
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      { code: 'UNAUTHORIZED' },
    ),
  ]
  const errorMessage = 'Unauthorized'
  const apolloError = new ApolloError({
    graphQLErrors,
    errorMessage,
  })

  renderWithRouter(
    <>
      <Route exact path="/">
        <ErrorHandler error={apolloError} />
      </Route>

      <Route exact path="/signin">
        Redirect Success
      </Route>
    </>,
  )

  expect(await findByText('Redirect Success')).toBeInTheDocument()
})
