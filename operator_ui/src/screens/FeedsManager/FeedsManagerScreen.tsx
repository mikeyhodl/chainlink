import React from 'react'
import { Redirect, useLocation } from 'react-router-dom'

import { FeedsManagerView } from './FeedsManagerView'
import { useFeedsManagersQuery } from 'src/hooks/useFeedsManagersQuery'
import { Loading } from 'src/components/Feedback/Loading'

export const FeedsManagerScreen: React.FC = () => {
  const location = useLocation()
  const { data, loading, error } = useFeedsManagersQuery()

  if (loading) {
    return <Loading />
  }

  if (error) {
    return <div>error</div> // TODO - Support error handling component
  }

  // We currently only support a single feeds manager, but plan to support more
  // in the future.
  const manager =
    data != undefined && data.feedsManagers.results[0]
      ? data.feedsManagers.results[0]
      : undefined

  if (manager) {
    return <FeedsManagerView data={manager} />
  }

  return (
    <Redirect
      to={{
        pathname: '/feeds_manager/new',
        state: { from: location },
      }}
    />
  )
}
