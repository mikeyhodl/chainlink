import * as React from 'react'

import { Route } from 'react-router-dom'
import { renderWithRouter, screen } from 'support/test-utils'
import { MockedProvider, MockedResponse } from '@apollo/client/testing'

import { buildFeedsManager } from 'support/factories/feedsManager'
import { FeedsManagerScreen } from './FeedsManagerScreen'
import { FEEDS_MANAGERS_QUERY } from 'src/hooks/useFeedsManagersQuery'

import globPath from 'test-helpers/globPath'

const { findByText } = screen

test('renders the page', async () => {
  const mocks: MockedResponse[] = [
    {
      request: {
        query: FEEDS_MANAGERS_QUERY,
      },
      result: {
        data: {
          feedsManagers: {
            results: [buildFeedsManager()],
          },
        },
      },
    },
  ]

  // Temporary until we switch it out for GQL
  global.fetch.getOnce(globPath('/v2/job_proposals'), { data: [] })

  renderWithRouter(
    <MockedProvider mocks={mocks} addTypename={false}>
      <Route>
        <FeedsManagerScreen />
      </Route>
    </MockedProvider>,
  )

  expect(await findByText('Feeds Manager')).toBeInTheDocument()
  expect(await findByText('Job Proposals')).toBeInTheDocument()
})

test('redirects when a manager does not exists', async () => {
  const mocks: MockedResponse[] = [
    {
      request: {
        query: FEEDS_MANAGERS_QUERY,
      },
      result: {
        data: {
          feedsManagers: {
            results: [],
          },
        },
      },
    },
  ]

  renderWithRouter(
    <>
      <Route exact path="/">
        <MockedProvider mocks={mocks} addTypename={false}>
          <FeedsManagerScreen />
        </MockedProvider>
      </Route>

      <Route path="/feeds_manager/new">Redirect Success</Route>
    </>,
  )

  expect(await findByText('Redirect Success')).toBeInTheDocument()
})
